package ve.gob.cenditel.murachi;


/**
 * Clase PresignParameters que representa el objeto que se mapea al JSON
 * que se envia a /archivos/pdfs
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
	
	private Boolean signatureVisible;
	
	private String signaturePage;
	
	private String xPos;
	
	private String yPos;
	
	private Boolean lastSignature;
	
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

	public Boolean getSignatureVisible() {
		return signatureVisible;
	}

	public void setSignatureVisible(Boolean signatureVisible) {
		this.signatureVisible = signatureVisible;
	}

	public String getxPos() {
		return xPos;
	}

	public void setxPos(String xPos) {
		this.xPos = xPos;
	}

	public String getSignaturePage() {
		return signaturePage;
	}

	public void setSignaturePage(String signaturePage) {
		this.signaturePage = signaturePage;
	}

	public String getyPos() {
		return yPos;
	}

	public void setyPos(String yPos) {
		this.yPos = yPos;
	}

	public Boolean getLastSignature() {
		return lastSignature;
	}

	public void setLastSignature(Boolean lastSignature) {
		this.lastSignature = lastSignature;
	}
}
