package com.company.incert.pkcs11j.provider;

import com.company.incert.pkcs11j.Pkcs11Constants;
import com.company.incert.pkcs11j.Pkcs11Exception;
import com.company.incert.pkcs11j.port.Pkcs11LibraryPort;
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
 * Because PKCS#11 sessions are not thread-safe for active operations (calling {@code C_SignInit} concurrently
 * yields {@code CKR_OPERATION_ACTIVE}), callers borrow a dedicated session per signing call and return it
 * in {@code finally}. Broken or logged-out sessions trigger one automatic reopen + re-login retry.
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
    private final char[] pin;
    private final int poolSize;
    private final ArrayBlockingQueue<Long> pool;
    private final Object loginLock = new Object();
    private final AtomicBoolean closed = new AtomicBoolean(false);

    public Pkcs11SessionPool(Pkcs11LibraryPort library, long slotId, char[] pin, int poolSize) {
        this.library = library;
        this.slotId = slotId;
        this.pin = pin != null ? pin.clone() : new char[0];
        this.poolSize = Math.max(1, poolSize);
        this.pool = new ArrayBlockingQueue<>(this.poolSize);
        initPool();
    }

    private void initPool() {
        long firstSession = openRoSession();
        try {
            loginIfPinPresent(firstSession);
        } catch (RuntimeException e) {
            safeCloseSession(firstSession);
            throw e;
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
        log.debug("Opened {} PKCS#11 RO sessions on slot {}", pool.size(), slotId);
    }

    public <T> T withSession(SessionCallback<T> callback) {
        ensureOpen();
        Long session = borrowSession();
        boolean returnToPool = true;
        try {
            return callback.execute(session);
        } catch (Pkcs11Exception e) {
            if (!e.isSessionInvalid() && !e.isNotLoggedIn()) {
                throw e;
            }
            returnToPool = false;
            safeCloseSession(session);
            log.warn("PKCS#11 session {} on slot {} invalidated/logged out ({}); reopening and retrying once",
                    session, slotId, e.getMessage());
            Long fresh = reopenAndLoginSession();
            boolean returnFresh = true;
            try {
                return callback.execute(fresh);
            } catch (RuntimeException retryEx) {
                if (retryEx instanceof Pkcs11Exception pEx && (pEx.isSessionInvalid() || pEx.isNotLoggedIn())) {
                    returnFresh = false;
                    safeCloseSession(fresh);
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
            try {
                return callback.execute(rwSession);
            } catch (Pkcs11Exception e) {
                if (!e.isNotLoggedIn()) {
                    throw e;
                }
                synchronized (loginLock) {
                    loginIfPinPresent(rwSession);
                }
                return callback.execute(rwSession);
            }
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
            if (i == 0 && pin.length > 0) {
                try {
                    library.cLogout(s);
                } catch (Exception ignored) {}
            }
            safeCloseSession(s);
        }
        Arrays.fill(pin, '\0');
    }

    private Long borrowSession() {
        try {
            Long session = pool.poll(BORROW_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (session != null) {
                return session;
            }
            // Pool busy beyond wait threshold: open an ephemeral RO session so caller can still progress
            return reopenAndLoginSession();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for PKCS#11 session on slot " + slotId, e);
        }
    }

    private long reopenAndLoginSession() {
        synchronized (loginLock) {
            long session = openRoSession();
            try {
                loginIfPinPresent(session);
                return session;
            } catch (RuntimeException e) {
                safeCloseSession(session);
                throw e;
            }
        }
    }

    private void loginIfPinPresent(long session) {
        if (pin.length == 0) {
            return;
        }
        long rv = library.cLogin(session, Pkcs11Constants.CKU_USER, pin);
        if (rv != Pkcs11Constants.CKR_OK && rv != Pkcs11Constants.CKR_USER_ALREADY_LOGGED_IN) {
            throw new Pkcs11Exception("C_Login", rv);
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

