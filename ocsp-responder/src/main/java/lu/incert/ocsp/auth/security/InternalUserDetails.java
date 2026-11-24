package lu.incert.ocsp.auth.security;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * {@link UserDetails} adapter wrapping {@link InternalPrincipal} for {@code SELF_MANAGEMENT} authentication.
 */
@Getter
public class InternalUserDetails implements UserDetails {

    private final InternalPrincipal principal;
    private final String passwordHash;
    private final boolean enabled;
    private final Collection<? extends GrantedAuthority> authorities;

    public InternalUserDetails(InternalPrincipal principal, String passwordHash, boolean enabled) {
        this.principal = principal;
        this.passwordHash = passwordHash;
        this.enabled = enabled;
        this.authorities = principal.roles().stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return principal.username();
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}

