package ve.gob.cenditel.murachi;


/**
 * Clase PresignParametersBdoc que representa el objeto que se mapea al JSON
 * que se envia a /archivos/bdocs
 * 
 * @author aaraujo
 *
 */
public class PresignParametersBdoc {

	private String fileId;
	
	private String certificate;
	
	private String city;
	
	private String state;
	
	private String postalCode;
	
	private String country;
	
	private String role;
	
	private Boolean addSignature;
	
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

	public String getCity() {
		return city;
	}

	public void setCity(String c) {
		this.city = c;
	}

	public String getState() {
		return state;
	}

	public void setState(String s) {
		this.state = s;
	}

	public String getPostalCode() {
		return postalCode;
	}

	public void setPostalCode(String p) {
		this.postalCode = p;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(String c) {
		this.country = c;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public Boolean getAddSignature() {
		return addSignature;
	}

	public void setAddSignature(Boolean addSignature) {
		this.addSignature = addSignature;
	}
}
