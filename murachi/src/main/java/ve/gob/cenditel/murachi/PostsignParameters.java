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
	
	private String containerId;
	
	public String getSignature() {
		return signature;
	}
	
	public void setSignature(String sig) {
		signature = sig;
	}

	public String getContainerId() {
		return containerId;
	}

	public void setContainerId(String containerId) {
		this.containerId = containerId;
	}

}
