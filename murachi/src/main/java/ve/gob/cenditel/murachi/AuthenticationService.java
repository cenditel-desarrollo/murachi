package ve.gob.cenditel.murachi;

import java.io.IOException;
//import java.util.Base64;
import java.util.StringTokenizer;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

/**
 * Clase para ejecutar el servicio de autenticacion basica HTTP.
 * 
 * @author aaraujo
 *
 */
public class AuthenticationService {
	
	final static Logger logger = Logger.getLogger(AuthenticationService.class);
	
	public boolean authenticate(String authCredentials) {

		if (null == authCredentials)
			return false;
		// header value format will be "Basic encodedstring" for Basic
		// authentication. Example "Basic YWRtaW46YWRtaW4="
		final String encodedUserPassword = authCredentials.replaceFirst("Basic"
				+ " ", "");
		String usernameAndPassword = null;
		try {
			//byte[] decodedBytes = Base64.getDecoder().decode(encodedUserPassword);
			
			// usando la clase Base64 de org.apache.commons.codec.binary.Base64
			byte[] decodedBytes = Base64.decodeBase64(encodedUserPassword);
			
			usernameAndPassword = new String(decodedBytes, "UTF-8");
		} catch (IOException e) {
			e.printStackTrace();
		}
		final StringTokenizer tokenizer = new StringTokenizer(
				usernameAndPassword, ":");
		final String username = tokenizer.nextToken();
		final String password = tokenizer.nextToken();
		
		logger.debug(username);
		logger.debug(password);
		
		

		// we have fixed the userid and password as admin
		// call some UserService/LDAP here
		boolean authenticationStatus = "admin".equals(username)
				&& "admin".equals(password);
		
		if (!authenticationStatus) {
			logger.error("Fallo la autenticación básica de HTTP; no se ejecuta el recurso");
		}
		
		
		return authenticationStatus;
	}
}