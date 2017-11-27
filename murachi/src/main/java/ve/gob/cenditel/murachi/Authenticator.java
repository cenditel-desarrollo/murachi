package ve.gob.cenditel.murachi;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import javax.ws.rs.NameBinding;

//@Authenticator annotation is the name binding annotation
/**
 * Autenticacion basica HTTP.
 * 
 * @author aaraujo
 *
 */
@NameBinding
@Retention(RetentionPolicy.RUNTIME)
public @interface Authenticator {}