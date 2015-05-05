package ve.gob.cenditel.murachi;


/**
 * Clase PresignParameters que representa el objeto que se mapea al JSON
 * que se envia a /archivos/prepararfirmapdf
 * 
 * @author aaraujo
 *
 */
public class PresignParameters {

	private String fileId;
	
	private String certificate;
	
	private String reason;
	
	private String location;
	
	private String contact;
	
	public String getFileId() {
		return fileId;
	}
	
	public void setFileId(String id) {
		fileId = id;
	}
	
	public String getCertificate() {
		return certificate;
	}
	
	public void setCertificate(String cert) {
		certificate = cert;
	}

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public String getContact() {
		return contact;
	}

	public void setContact(String contact) {
		this.contact = contact;
	}
}
