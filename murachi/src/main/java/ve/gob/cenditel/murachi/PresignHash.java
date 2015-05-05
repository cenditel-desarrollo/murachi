package ve.gob.cenditel.murachi;


/**
 * Clase PresignHash que representa el objeto que se mapea al JSON
 * que se envia al cliente con el hash que se debe firmar
 * 
 * @author aaraujo
 *
 */
public class PresignHash {
	
	private String hash;
	
	private String error;
	
	public String getHash() {
		return hash;
	}
	
	public void setHash(String h) {
		hash = h;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}
	

}
