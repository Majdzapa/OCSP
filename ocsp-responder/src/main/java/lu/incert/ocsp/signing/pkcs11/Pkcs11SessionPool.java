package lu.incert.ocsp.signing.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Thread-safe bounded pool of PKCS#11 RO sessions ({@code CK_SESSION_HANDLE}) for a single token slot.
 * <p>
 * Strict Pattern 2 (Runtime Activation): the PIN is passed only to {@code C_Login} during pool initialization
 * and immediately wiped from memory. On {@code CKR_USER_NOT_LOGGED_IN}, {@code onLoggedOut} fires without
 * attempting any silent re-login.
 */
public final class Pkcs11SessionPool implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11SessionPool.class);
    private static final long BORROW_TIMEOUT_SECONDS = 30L;

    @FunctionalInterface
    public interface SessionCallback<T> {
        T execute(long sessionHandle);
    }

    private final Pkcs11LibraryPort library;
    private final long slotId;
    private final boolean authenticated;
    private final int poolSize;
    private final ArrayBlockingQueue<Long> pool;
    private final Runnable onLoggedOut;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    public Pkcs11SessionPool(Pkcs11LibraryPort library, long slotId, char[] pin, int poolSize) {
        this(library, slotId, pin, poolSize, null);
    }

    public Pkcs11SessionPool(
            Pkcs11LibraryPort library,
            long slotId,
            char[] pin,
            int poolSize,
            Runnable onLoggedOut) {
        this.library = library;
        this.slotId = slotId;
        this.authenticated = pin != null && pin.length > 0;
        this.poolSize = Math.max(1, poolSize);
        this.pool = new ArrayBlockingQueue<>(this.poolSize);
        this.onLoggedOut = onLoggedOut;
        initPool(pin);
    }

    private void initPool(char[] rawPin) {
        char[] loginPin = rawPin != null ? rawPin.clone() : new char[0];
        if (rawPin != null) {
            Arrays.fill(rawPin, '\0');
        }
        long firstSession = openRoSession();
        try {
            if (loginPin.length > 0) {
                long rv = library.cLogin(firstSession, Pkcs11Constants.CKU_USER, loginPin);
                if (rv != Pkcs11Constants.CKR_OK && rv != Pkcs11Constants.CKR_USER_ALREADY_LOGGED_IN) {
                    throw new Pkcs11Exception("C_Login", rv);
                }
            }
        } catch (RuntimeException e) {
            safeCloseSession(firstSession);
            throw e;
        } finally {
            Arrays.fill(loginPin, '\0');
        }
        pool.add(firstSession);

        for (int i = 1; i < poolSize; i++) {
            try {
                pool.add(openRoSession());
            } catch (RuntimeException e) {
                log.warn("Could only open {}/{} pooled sessions on slot {}: {}", i, poolSize, slotId, e.getMessage());
                break;
            }
        }
        log.debug("Opened {} PKCS#11 RO sessions on slot {} (PIN wiped immediately after C_Login)", pool.size(), slotId);
    }

    public <T> T withSession(SessionCallback<T> callback) {
        ensureOpen();
        Long session = borrowSession();
        boolean returnToPool = true;
        try {
            return callback.execute(session);
        } catch (Pkcs11Exception e) {
            if (e.isNotLoggedIn()) {
                returnToPool = false;
                safeCloseSession(session);
                notifyLoggedOut();
                throw e;
            }
            if (!e.isSessionInvalid()) {
                throw e;
            }
            returnToPool = false;
            safeCloseSession(session);
            log.warn("PKCS#11 session {} on slot {} invalidated ({}); reopening fresh session and retrying once",
                    session, slotId, e.getMessage());
            Long fresh = openRoSession();
            boolean returnFresh = true;
            try {
                return callback.execute(fresh);
            } catch (RuntimeException retryEx) {
                if (retryEx instanceof Pkcs11Exception pEx) {
                    if (pEx.isNotLoggedIn()) {
                        returnFresh = false;
                        safeCloseSession(fresh);
                        notifyLoggedOut();
                    } else if (pEx.isSessionInvalid()) {
                        returnFresh = false;
                        safeCloseSession(fresh);
                    }
                }
                throw retryEx;
            } finally {
                if (returnFresh && !closed.get()) {
                    offerOrClose(fresh);
                }
            }
        } finally {
            if (returnToPool) {
                if (!closed.get()) {
                    offerOrClose(session);
                } else {
                    safeCloseSession(session);
                }
            }
        }
    }

    public <T> T withRwSession(SessionCallback<T> callback) {
        ensureOpen();
        long rwSession = openRwSession();
        try {
            return callback.execute(rwSession);
        } catch (Pkcs11Exception e) {
            if (e.isNotLoggedIn()) {
                notifyLoggedOut();
            }
            throw e;
        } finally {
            safeCloseSession(rwSession);
        }
    }

    public int availableSessions() {
        return pool.size();
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        List<Long> remaining = new ArrayList<>();
        pool.drainTo(remaining);
        for (int i = 0; i < remaining.size(); i++) {
            long s = remaining.get(i);
            if (i == 0 && authenticated) {
                try {
                    library.cLogout(s);
                } catch (Exception ignored) {}
            }
            safeCloseSession(s);
        }
    }

    private Long borrowSession() {
        try {
            Long session = pool.poll(BORROW_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (session != null) {
                return session;
            }
            return openRoSession();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for PKCS#11 session on slot " + slotId, e);
        }
    }

    private void notifyLoggedOut() {
        if (onLoggedOut != null) {
            try {
                onLoggedOut.run();
            } catch (Exception e) {
                log.warn("Error notifying logout listener for slot {}: {}", slotId, e.getMessage());
            }
        }
    }

    private long openRoSession() {
        return library.cOpenSession(slotId, Pkcs11Constants.CKF_SERIAL_SESSION);
    }

    private long openRwSession() {
        return library.cOpenSession(slotId, Pkcs11Constants.CKF_SERIAL_SESSION | Pkcs11Constants.CKF_RW_SESSION);
    }

    private void offerOrClose(Long session) {
        if (!pool.offer(session)) {
            safeCloseSession(session);
        }
    }

    private void safeCloseSession(long session) {
        try {
            library.cCloseSession(session);
        } catch (Exception ignored) {}
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("PKCS#11 session pool is closed for slot " + slotId);
        }
    }
}

