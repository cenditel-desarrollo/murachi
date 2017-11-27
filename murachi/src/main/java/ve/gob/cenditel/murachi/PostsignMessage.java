package ve.gob.cenditel.murachi;

/**
 * Clase PostsignMessage que representa el objeto que se mapea al JSON
 * que se envia al cliente al terminar la firma
 * 
 * @author aaraujo
 *
 */
public class PostsignMessage {

	private String message;

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
}
