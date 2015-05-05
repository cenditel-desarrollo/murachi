package ve.gob.cenditel.murachi;


/**
 * Clase PostsignParameters que representa el objeto que se mapea al JSON
 * que se envia a /archivos/terminarfirmapdf
 * 
 * @author aaraujo
 *
 */
public class PostsignParameters {
	
	private String signature;
	
	public String getSignature() {
		return signature;
	}
	
	public void setSignature(String sig) {
		signature = sig;
	}

}
