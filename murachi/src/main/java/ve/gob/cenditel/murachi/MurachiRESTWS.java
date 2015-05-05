package ve.gob.cenditel.murachi;

import static java.util.Arrays.asList;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.UUID;
import java.text.DateFormat;
import java.text.SimpleDateFormat;













































import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.json.JSONArray;
import org.json.JSONObject;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.exceptions.InvalidPdfException;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.SignaturePermissions;
import com.itextpdf.text.pdf.security.VerificationException;

import ee.sk.digidoc.CertValue;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.DigiDocGenFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.Container.DocumentType;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProductionPlace;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.Container.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignatureNotFoundException;
import org.digidoc4j.impl.DDocContainer;
import org.digidoc4j.impl.DDocSignature;
import org.digidoc4j.impl.ValidationResultForDDoc;
import org.digidoc4j.signers.PKCS12Signer;



@Path("/archivos")
public class MurachiRESTWS {

	private static final String SERVER_UPLOAD_LOCATION_FOLDER = "/tmp/"; 
	
	public static final String ACRAIZ = "/tmp/CERTIFICADO-RAIZ-SHA384.crt";
	public static final String PSCFII = "/tmp/PSCFII-SHA256.crt";	
	public static final String GIDSI = "/tmp/gidsi.crt";
	
	
	private static final String ANSI_RED = "^[[31m";
	private static final String ANSI_RESET = "^[[0m";
	
	// para reportes de advertencias de BDOC
	private static boolean bdocWarnings = true;
	
	// para reportes en modo verbose de BDOC
	private static boolean bdocVerboseMode = true;

        	
	/**
	 * Carga un archivo pasado a través de un formulario y retorna 
	 * un json con el id del archivo en el servidor para futuras consultas
	 * 
	 * @param uploadedInputStream stream para obtener el archivo
	 * @param fileDetails datos del archivo
	 * @return
	 */
/*	
	@POST
	@Path("/")
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	@Produces(MediaType.APPLICATION_JSON)
	public Response uploadFile(
			@FormDataParam("upload") InputStream uploadedInputStream,
			@FormDataParam("upload") FormDataContentDisposition fileDetails) {
		
		//TODO manejar las excepciones correctamente
		if (uploadedInputStream == null) {
			System.out.println("uploadedInputStream == null");
		}
		
		if (fileDetails == null) {
			System.out.println("fileDetails == null");
		}
				
		String fileId = UUID.randomUUID().toString();
		System.out.println(fileId);
		
		saveToDisk(uploadedInputStream, fileDetails, fileId);
		
		try {
			uploadedInputStream.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("fileId", fileId);
		
		System.out.println("File saved to server location : " + SERVER_UPLOAD_LOCATION_FOLDER + fileId);
		String result = jsonObject.toString();
		
		return Response.status(200).entity(result).build();
	}
*/
	
	/**
	 * Carga un archivo pasado a través de un formulario y retorna 
	 * un json con el id del archivo en el servidor para futuras consultas
	 * 
	 * @param uploadedInputStream stream para obtener el archivo
	 * @param fileDetails datos del archivo
	 * @return
	 */
	@POST
	@Path("/")
	@Consumes(MediaType.MULTIPART_FORM_DATA)
	@Produces(MediaType.APPLICATION_JSON)
	public Response uploadFileAndVerify(
			@FormDataParam("upload") InputStream uploadedInputStream,
			@FormDataParam("upload") FormDataContentDisposition fileDetails) {
		
		//TODO manejar las excepciones correctamente
		if (uploadedInputStream == null) {
			System.out.println("uploadedInputStream == null");
		}
		
		if (fileDetails == null) {
			System.out.println("fileDetails == null");
		}
				
		String fileId = UUID.randomUUID().toString();
		System.out.println(fileId);
		
		saveToDisk(uploadedInputStream, fileDetails, fileId);
		
		try {
			uploadedInputStream.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("File saved to server location : " + SERVER_UPLOAD_LOCATION_FOLDER + fileId);
		
		JSONObject jsonObject = new JSONObject();
					
		jsonObject = verifyALocalFile(fileId);
		
		return Response.status(200).entity(jsonObject.toString()).build();
	}
	
	/**
	 * Escribe un archivo en el sistema de archivos 
	 * @param uploadedInputStream
	 * @param fileDetails
	 * @param fileId identificador unico del archivo de acuerdo a UUIDs
	 */
	private void saveToDisk(InputStream uploadedInputStream, FormDataContentDisposition fileDetails, String fileId) {
		
		String uploadedFileLocation = SERVER_UPLOAD_LOCATION_FOLDER + /*fileDetails.getFileName()*/ fileId;
		
		System.out.println("uploadedFileLocation: " + uploadedFileLocation);
		
		try {
			OutputStream out = new FileOutputStream(new File(uploadedFileLocation));
			int read = 0;
			byte[] bytes = new byte[1024];
			
			out = new FileOutputStream(new File(uploadedFileLocation));
			while ((read = uploadedInputStream.read(bytes)) != -1) {
				out.write(bytes, 0, read);
				
			}
			out.flush();
			out.close();
		}
		catch(IOException e) {
			e.printStackTrace();
		}
	}
	
	
	/**
	 * Verifica si un archivo posee firmas electronicas y retorna informacion
	 * de las mismas en un json
	 * @param idFile identificador del archivo a verificar
	 * @return JSON con informacion de las firmas
	 */
	@GET
	@Path("/{idFile}")
	@Produces("application/json")
	public Response verifyAFile(@PathParam("idFile") String idFile) {
		
		System.out.println("/{idFile}");
		
		String result = "";
		String file = SERVER_UPLOAD_LOCATION_FOLDER + idFile;
		
		File tmpFile = new File(file);
		
		JSONObject jsonObject = new JSONObject();
		
		if (!tmpFile.exists()) {
			System.out.println("File : " + file + " does not exists.");
			jsonObject.put("fileExist", "false");
			
		}else{
			System.out.println("File : " + file + " exists.");
			jsonObject.put("fileExist", "true");
			
			String mime = getMimeType(file);
			System.out.println("mimetype : " + mime);
			
			if (mime.equals("application/pdf")){
				System.out.println(" PDF ");
				
				jsonObject = verifySignaturesInPdf(file);
				
			}else{
				System.out.println("BDOC");
				//jsonObject.put("formato", "BDOC");
				//jsonObject.put("resultado", "NO IMPLEMENTADO");
				
				jsonObject = verifySignaturesInBdoc(file);
			}			
		}
		result = jsonObject.toString();
		return Response.status(200).entity(result).build();
	}
	
	/**
	 * Verifica si un archivo local posee firmas electronicas y retorna informacion
	 * de las mismas en un json.
	 * 
	 * @param idFile identificador del archivo a verificar
	 * @return JSONObject con informacion de las firmas
	 */
	public JSONObject verifyALocalFile(String idFile) {
		
		System.out.println("verifyALocalFile: " + idFile);
		
		String file = SERVER_UPLOAD_LOCATION_FOLDER + idFile;
		
		File tmpFile = new File(file);
		
		JSONObject jsonObject = new JSONObject();
		
		if (!tmpFile.exists()) {
			System.out.println("File : " + file + " does not exists.");
			jsonObject.put("fileExist", "false");
			
		}else{
			System.out.println("File : " + file + " exists.");
			jsonObject.put("fileExist", "true");
			
			String mime = getMimeType(file);
			System.out.println("mimetype : " + mime);
			
			if (mime.equals("application/pdf")){
				System.out.println(" PDF ");
				
				jsonObject = verifySignaturesInPdf(file);
				
			//}else if (mime.equals("application/vnd.etsi.asic-e+zip")){
			}else if (mime.equals("application/zip") ){
				System.out.println("BDOC");				
				//jsonObject.put("formato", "BDOC");
				//jsonObject.put("resultado", "NO IMPLEMENTADO");
				
				jsonObject = verifySignaturesInBdoc(file);
			}else{
				System.out.println("extension no reconocida");
				jsonObject.put("fileExist", "true");
				jsonObject.put("error", "extension not supported");				
			}
		}
		return jsonObject;
	}
	
	
	/**
	 * Retorna un JSON con informacion de las firmas del documento PDF
	 * @param pdfFile archivo pdf a verificar
	 * @return JSON con informacion de las firmas del documento PDF
	 */
	private JSONObject verifySignaturesInPdf(String pdfFile) {
		
		JSONObject jsonSignatures = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		
		try {
			
			Security.addProvider(new BouncyCastleProvider());
			
			PdfReader reader = new PdfReader(pdfFile);
			AcroFields af = reader.getAcroFields();
			ArrayList<String> names = af.getSignatureNames();
			if (names.size() <= 0) {
				jsonSignatures.put("signatureNumber", "0");
			}else{
				
				jsonSignatures.put("fileExist", "true");
				jsonSignatures.put("numberOfSignatures", names.size());
								
				HashMap<String, String> signatureInformation;
				
				for (String name : names) {
					System.out.println("===== " + name + " =====");
					signatureInformation = verifySignature(af, name);
					System.out.println("signatureInformation.size " + signatureInformation.size());
					
					JSONObject jo = getJSONFromASignature(signatureInformation);
					System.out.println("jo:  " + jo.toString());
					jsonArray.put(jo);
				}	
				jsonSignatures.put("signatures", jsonArray);
				System.out.println("jsonSignatures :  " + jsonSignatures.toString());
				
			}
			
		} catch (IOException e) {		
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
				
		return jsonSignatures;		
	}
	
	/**
	 * Chequea la integridad de una revision basada en una firma electronica
	 * @param fields Campos
	 * @param name nombre de la firma
	 * @return HashMap con campos de informacion de la firma electronica
	 */
	public HashMap<String, String> verifySignature(AcroFields fields, String name) throws GeneralSecurityException, IOException {
				
		HashMap<String, String> integrityMap = new HashMap<String, String>();
		
		System.out.println("Signature covers whole document: " + fields.signatureCoversWholeDocument(name));
		
		integrityMap.put("signatureCoversWholeDocument", Boolean.toString(fields.signatureCoversWholeDocument(name)));
		
		int revision = fields.getRevision(name);
		System.out.println("Document revision: " + fields.getRevision(name) + " of " + fields.getTotalRevisions());		
		integrityMap.put("documentRevision", Integer.toString(fields.getRevision(name)));
		
		System.out.println("Total Document revisions: " + fields.getTotalRevisions());
		integrityMap.put("totalDocumentRevisions",  Integer.toString(fields.getTotalRevisions()));
				
		PdfPKCS7 pkcs7 = fields.verifySignature(name);
        System.out.println("Integrity check OK? " + pkcs7.verify());
        integrityMap.put("integrityCheck", Boolean.toString(pkcs7.verify()));
	
        System.out.println("Digest Algorithm: " + pkcs7.getHashAlgorithm());
        integrityMap.put("digestAlgorithm", pkcs7.getHashAlgorithm());
        
        System.out.println("Encryption Algorithm: " + pkcs7.getEncryptionAlgorithm());
        integrityMap.put("encryptionAlgorithm", pkcs7.getEncryptionAlgorithm());
        
        System.out.println("Filter subtype: " + pkcs7.getFilterSubtype());
        integrityMap.put("filterSubtype", pkcs7.getFilterSubtype().toString());
        
        X509Certificate cert = (X509Certificate) pkcs7.getSigningCertificate();
		System.out.println("Name of the signer: " + CertificateInfo.getSubjectFields(cert).getField("CN"));
		integrityMap.put("nameOfTheSigner", CertificateInfo.getSubjectFields(cert).getField("CN"));
        
		if (pkcs7.getSignName() != null){
			System.out.println("Alternative name of the signer: " + pkcs7.getSignName());
			integrityMap.put("alternativeNameOfTheSigner", pkcs7.getSignName());			
		}else{
			System.out.println("Alternative name of the signer: " + "null");
			integrityMap.put("alternativeNameOfTheSigner", "");
		}
		
		SimpleDateFormat date_format = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss.SS");
		System.out.println("Signed on: " + date_format.format(pkcs7.getSignDate().getTime()));
		integrityMap.put("signedOn", date_format.format(pkcs7.getSignDate().getTime()).toString());
		
		if (pkcs7.getTimeStampDate() != null) {
			System.out.println("TimeStamp: " + date_format.format(pkcs7.getTimeStampDate().getTime()));
			integrityMap.put("timeStamp", date_format.format(pkcs7.getTimeStampDate().getTime()).toString());
			TimeStampToken ts = pkcs7.getTimeStampToken();
			System.out.println("TimeStamp service: " + ts.getTimeStampInfo().getTsa());
			integrityMap.put("timeStampService", ts.getTimeStampInfo().getTsa().toString());
			System.out.println("Timestamp verified? " + pkcs7.verifyTimestampImprint());
			integrityMap.put("timeStampVerified", Boolean.toString(pkcs7.verifyTimestampImprint()));
		}else{
			System.out.println("TimeStamp: " + "null");
			integrityMap.put("timeStamp", "null");
			
			System.out.println("TimeStamp service: " + "null");
			integrityMap.put("timeStampService", "null");
			
			System.out.println("Timestamp verified?: " + "null");
			integrityMap.put("timeStampVerified", "null");
		}
		
		System.out.println("Location: " + pkcs7.getLocation());
		integrityMap.put("location", pkcs7.getLocation());		
		
		System.out.println("Reason: " + pkcs7.getReason());
		integrityMap.put("reason", pkcs7.getReason());
		
		PdfDictionary sigDict = fields.getSignatureDictionary(name);
		PdfString contact = sigDict.getAsString(PdfName.CONTACTINFO);
		if (contact != null){
			System.out.println("Contact info: " + contact);
			integrityMap.put("contactInfo", contact.toString());			
		}else{
			System.out.println("Contact info: " + "null");
			integrityMap.put("contactInfo", "null");
		}
			
		SignaturePermissions perms = null;
		perms = new SignaturePermissions(sigDict, perms);
		System.out.println("Signature type: " + (perms.isCertification() ? "certification" : "approval"));
		integrityMap.put("signatureType", (perms.isCertification() ? "certification" : "approval"));
		
		
		KeyStore ks = setupKeyStore();
		
		Certificate[] certs = pkcs7.getSignCertificateChain();
		Calendar cal = pkcs7.getSignDate();
		List<VerificationException> errors = CertificateVerification.verifyCertificates(certs, ks, cal);
		if (errors.size() == 0){		
			System.out.println("Certificates verified against the KeyStore");
			integrityMap.put("certificatesVerifiedAgainstTheKeyStore", "true");
		}
		else{
			System.out.println(errors);
			integrityMap.put("certificatesVerifiedAgainstTheKeyStore", "false");
		}
		
		
		X509Certificate certificateTmp = (X509Certificate) certs[0];
		System.out.println("=== Certificate " + Integer.toString(revision) + " ===");

		HashMap<String, String> signerCertificateMap = getSignerCertificateInfo(certificateTmp, cal.getTime());
		for (Entry<String, String> entry : signerCertificateMap.entrySet()) {
			integrityMap.put(entry.getKey(), entry.getValue());
		}
		
		return integrityMap;
	}
	
	/**
	 * Construye un objeto JSON a partir del HashMap pasado como argumento
	 * @param hashMap HashMap que contiene los elementos para construir el JSON
	 * @return objeto JSON a partir del HashMap pasado como argumento
	 */
	public JSONObject getJSONFromASignature(HashMap<String, String> hashMap) {
		
		JSONObject jsonSignature = new JSONObject();
		
		for (Entry<String, String> entry : hashMap.entrySet()) {
		    System.out.println("Key = " + entry.getKey() + ", Value = " + entry.getValue());
		    jsonSignature.put(entry.getKey(), entry.getValue());
		}		
		return jsonSignature;		
	}
	
	/**
	 * Carga el KeyStore con certificados confiables para la verificacion de certificados
	 * de firmas
	 * @return KeyStore con certificados confiables
	 */
	private KeyStore setupKeyStore() {
		
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance(KeyStore.getDefaultType());
			
			ks.load(null, null);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			ks.setCertificateEntry("acraiz",cf.generateCertificate(new FileInputStream(ACRAIZ)));
			ks.setCertificateEntry("pscfii",cf.generateCertificate(new FileInputStream(PSCFII)));
			ks.setCertificateEntry("gidsi",cf.generateCertificate(new FileInputStream(GIDSI)));
			
			
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		return ks;
	}
	
	/**
	 * Obtiene informacion del certificado firmante de una revision
	 * @param cert certificado firmante
	 * @param signDate fecha en que se realizo la firma
	 * @return informacion del certificado firmante de una revision en forma de HashMap
	 */
	public HashMap<String, String> getSignerCertificateInfo(X509Certificate cert, Date signDate) {
		
		HashMap<String, String> signerCertificateMap = new HashMap<String, String>();
		
		System.out.println("Issuer: " + cert.getIssuerDN());
		signerCertificateMap.put("signerCertificateIssuer", cert.getIssuerDN().toString());
		
		
		System.out.println("Subject: " + cert.getSubjectDN());
		signerCertificateMap.put("signerCertificateSubject", cert.getSubjectDN().toString());
		
		SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
		System.out.println("Valid from: " + date_format.format(cert.getNotBefore()));
		signerCertificateMap.put("signerCertificateValidFrom", date_format.format(cert.getNotBefore()).toString());
		
		System.out.println("Valid to: " + date_format.format(cert.getNotAfter()));
		signerCertificateMap.put("signerCertificateValidTo", date_format.format(cert.getNotAfter()).toString());
		
		try {
			cert.checkValidity(signDate);
			System.out
					.println("The certificate was valid at the time of signing.");
			signerCertificateMap.put("signerCertificateValidAtTimeOfSigning", "true");
		} catch (CertificateExpiredException e) {
			System.out
					.println("The certificate was expired at the time of signing.");
			signerCertificateMap.put("signerCertificateExpiredAtTimeOfSigning", "true");
		} catch (CertificateNotYetValidException e) {
			System.out
					.println("The certificate wasn't valid yet at the time of signing.");
			signerCertificateMap.put("signerCertificateNotValidYetAtTimeOfSigning", "true");
		}
		try {
			cert.checkValidity();
			System.out.println("The certificate is still valid.");
			signerCertificateMap.put("signerCertificateStillValid", "true");
		} catch (CertificateExpiredException e) {
			System.out.println("The certificate has expired.");
			signerCertificateMap.put("signerCertificateHasExpired", "true");
		} catch (CertificateNotYetValidException e) {
			System.out.println("The certificate isn't valid yet.");
			signerCertificateMap.put("signerCertificateNotValidYet", "true");
		}
		return signerCertificateMap;
	}
	
	
	/**
	 * Ejecuta el proceso de presign o preparacion de firma de documento pdf.
	 * 
	 * Estructura del JSON que recibe la funcion:
	 * 
	 * 	{"fileId":"file_id",				
	 *	"certificate":"hex_cert_value",
	 *  "reason":"reason",
	 *  "location":"location",
	 *  "contact":"contact"
	 *  }
	 * 
	 * 
	 * @param presignPar JSON con los parametros de preparacion: Id del archivo y certificado
	 * firmante
	 * @param req objeto request para crear una sesion y mantener elementos del 
	 * pdf en la misma.
	 * 
	 */
	@POST
	@Path("/pdfs")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	//public PresignHash presignPdf(PresignParameters presignPar, @Context HttpServletRequest req) {
	public Response presignPdf(PresignParameters presignPar, @Context HttpServletRequest req) {
		
		String result = null;
		
		PresignHash presignHash = new PresignHash();

		// obtener el id del archivo 
		String fileId = presignPar.getFileId();
		
		// cadena con el certificado
		String certHex = presignPar.getCertificate();
		System.out.println("certificado en Hex: " + certHex);

		String reason = presignPar.getReason();
		
		String location = presignPar.getLocation();
		
		String contact = presignPar.getContact();
		
		
		String pdf = SERVER_UPLOAD_LOCATION_FOLDER + fileId;
		System.out.println("archivo a firmar: " + pdf);
		
		String mime = getMimeType(pdf);
		
		if (!mime.equals("application/pdf")){
			presignHash.setError("El archivo que desea firmar no es un PDF.");
			presignHash.setHash("");
			//return presignHash;
									
			//result = presignHash.toString();
			return Response.status(400).entity(presignHash).build();
			
		}
			
				
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			Certificate[] chain = new Certificate[1];
			
			InputStream in = new ByteArrayInputStream(hexStringToByteArray(certHex));
			chain[0] = factory.generateCertificate(in);
			
			if (chain[0] == null) {
				System.out.println("error chain[0] == null");
			}else {
				
				System.out.println("se cargo el certificado correctamente");
				System.out.println(chain[0].toString());
			}			
			
			PdfReader reader = new PdfReader(pdf);			
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			
			//PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');
			PdfStamper stamper = null;
			
			
			if (pdfAlreadySigned(reader)){
				stamper = PdfStamper.createSignature(reader, baos, '\0', null, true);
			}else{
				stamper = PdfStamper.createSignature(reader, baos, '\0');
			}

			// crear la apariencia de la firma
	    	PdfSignatureAppearance sap = stamper.getSignatureAppearance();
	    		    	
	    	sap.setReason(reason);
	    	sap.setLocation(location);
	    	sap.setContact(contact);
	    	
	    	//sap.setVisibleSignature(new Rectangle(36, 748, 144,780),1, "sig");
	    	
	    	if (!pdfAlreadySigned(reader)){
	    		sap.setVisibleSignature(new Rectangle(36, 748, 144, 780),1, "sig1");
			}else{
				int idSig = numberOfSignatures(reader)+1;
				//sap.setVisibleSignature(new Rectangle(36, 700, 144, 732),1, "sig"+Integer.toString(idSig));
				sap.setVisibleSignature(
						new Rectangle(36, (748-(numberOfSignatures(reader)*38)), 144, (780-(numberOfSignatures(reader)*38))),
							1, "sig"+Integer.toString(idSig));
			}
	    	
	    	sap.setCertificate(chain[0]);
	    	
	    	// crear la estructura de la firma
	    	PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
	    	
	    	
	    	dic.setReason(sap.getReason());
	    	dic.setLocation(sap.getLocation());
	    	dic.setContact(sap.getContact());
	    	dic.setDate(new PdfDate(sap.getSignDate()));
	    	
	    	sap.setCryptoDictionary(dic);
	    	
	    	HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer> ();
	    	exc.put(PdfName.CONTENTS, new Integer(8192 * 2 + 2));
	    	sap.preClose(exc);
	    	
	    	ExternalDigest externalDigest = new ExternalDigest() {
	    		public MessageDigest getMessageDigest(String hashAlgorithm)
	    		throws GeneralSecurityException {
	    			return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
	    		}
	    	};
			
			
	    	PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", null, externalDigest, false);
	    	
	    	InputStream data = sap.getRangeStream();
	    	
	    	byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));
	    	
	    	Calendar cal = Calendar.getInstance();
	    	byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, null, null, CryptoStandard.CMS);
	    	
	    	sh = DigestAlgorithms.digest(new ByteArrayInputStream(sh), externalDigest.getMessageDigest("SHA256"));
	    	
	    	System.out.println("sh length: "+ sh.length);
	    	    	
	    	String hashToSign = byteArrayToHexString(sh);
	    	System.out.println("***************************************************************");
	    	System.out.println("HASH EN HEXADECIMAL:");
	    	System.out.println(hashToSign);
	    	System.out.println("length: " +hashToSign.length());	
	    	System.out.println("***************************************************************");
			
	    	DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date date = new Date();
			System.out.println(dateFormat.format(date));
			//String d = dateFormat.format(date);
			
			
			// almacenar los objetos necesarios para realizar el postsign en una sesion
			HttpSession session = req.getSession(true);
			session.setAttribute("hashToSign", hashToSign);
			
			session.setAttribute("stamper", stamper);
			session.setAttribute("sgn", sgn);
			session.setAttribute("hash", hash);
			session.setAttribute("cal", cal);
			session.setAttribute("sap", sap);
			session.setAttribute("baos", baos);
			session.setAttribute("fileId", fileId);
			
			presignHash.setHash(hashToSign);
			presignHash.setError("");
				
			
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InvalidPdfException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			presignHash.setError("No se pudo leer el archivo PDF en el servidor");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
						
			
		} catch (DocumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
		return Response.status(200).entity(presignHash).build();
		//return presignHash;
			
	}
	
	/**
	 * Retorna verdadero si el archivo pdf pasado como argumento ya esta firmado.
	 * 
	 * @param pdfReader objeto PdfReader asociado al documento pdf
	 * @return si el archivo pdf pasado como argumento ya esta firmado.
	 * @throws IOException 
	 */
	private Boolean pdfAlreadySigned(PdfReader pdfReader) throws IOException {
		Security.addProvider(new BouncyCastleProvider());
		
		AcroFields af = pdfReader.getAcroFields();
		ArrayList<String> names = af.getSignatureNames();
		if (names.size() <= 0) {
			return false;
		}else{
			return true;
		}
	}
	
	/**
	 * Retorna el número de firmas del documento 
	 * @param pdfReader objeto PdfReader asociado al documento pdf 
	 * @return número de firmas del documento
	 */
	private int numberOfSignatures(PdfReader pdfReader) {
		Security.addProvider(new BouncyCastleProvider());
		
		AcroFields af = pdfReader.getAcroFields();
		ArrayList<String> names = af.getSignatureNames();
		return names.size();		
	}
	
	
	/**
	 * Ejecuta el proceso de postsign o completacion de firma de documento pdf
	 * @param postsignPar JSON con los parametros de postsign: signature realizada a partir 
	 * del hardware criptografico en el navegador.
	 * @param req objeto request para crear una sesion y mantener elementos del 
	 * pdf en la misma.
	 * @throws IOException 
	 */
	@POST
	@Path("/pdfs/resenas")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)	
	public Response postsignPdf(PostsignParameters postsignPar, @Context HttpServletRequest req) throws IOException {
		
		
		// cadena resultado de la funcion
		String result = "";
				
		// cadena con la firma
		String signature = postsignPar.getSignature();
		System.out.println("firma en Hex: " + signature);
		
		HttpSession session = req.getSession(false);
		
		String fileId = (String) session.getAttribute("fileId");
		System.out.println("fileId: " + fileId);
		
		PdfStamper stamper = (PdfStamper) session.getAttribute("stamper");
		
		PdfPKCS7 sgn = (PdfPKCS7) session.getAttribute("sgn");
		
		byte[] hash = (byte[]) session.getAttribute("hash");
		
		Calendar cal = (Calendar) session.getAttribute("cal");
		
		PdfSignatureAppearance sap = (PdfSignatureAppearance) session.getAttribute("sap");
		
		ByteArrayOutputStream os = (ByteArrayOutputStream) session.getAttribute("baos");
		
		if (sgn == null) {
			System.out.println("sgn == null");
		}
		if (hash == null) {
			System.out.println("hash == null");
		}
		if (cal == null) {
			System.out.println("cal == null");
		}
		if (sap == null) {
			System.out.println("sap == null");
		}
		if (os == null) {
			System.out.println("os == null");
		}
		
		
		
		// convertir signature en bytes		
		byte[] signatureInBytes = hexStringToByteArray(signature);
				
		// completar el proceso de firma
		sgn.setExternalDigest(signatureInBytes, null, "RSA");
		byte[] encodeSig = sgn.getEncodedPKCS7(hash, cal, null, null, null, CryptoStandard.CMS);
		byte[] paddedSig = new byte[8192];
		System.arraycopy(encodeSig, 0, paddedSig, 0, encodeSig.length);
		PdfDictionary dic2 = new PdfDictionary();
		dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
		try {
			sap.close(dic2);
			
			stamper.close();
			System.out.println("stamper.close");
			
		}catch(DocumentException e) {
			
			System.out.println("throw new IOException");
			throw new IOException(e);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("IOException e");
			e.printStackTrace();
			
		}
		
		String signedPdf = SERVER_UPLOAD_LOCATION_FOLDER + fileId + "-signed.pdf";
		
		FileOutputStream signedFile = new FileOutputStream(signedPdf);
		
		os.writeTo(signedFile);
		os.flush();
		
		
		
		// en este punto el archivo pdf debe estar disponible en la ruta
		// SERVER_UPLOAD_LOCATION_FOLDER + fileId;
		
		// llamar a una funcion que permita descargar el archivo
		
		result = "Archivo firmado correctamente";
		System.out.println("Archivo firmado correctamente");
		
			
		PostsignMessage message = new PostsignMessage();
		//message.setMessage(SERVER_UPLOAD_LOCATION_FOLDER + fileId + "-signed.pdf");
		message.setMessage(fileId + "-signed.pdf");
		return Response.status(200).entity(message).build();
	}
	
	/**
	 * Descarga el archivo pdf pasado como argumento.
	 * @param idFile nombre del archivo pdf a descargar
	 * @return archivo pdf pasado como argumento.
	 */
	@GET
	@Path("/pdfs/{idFile}")
	public Response getPdfSigned(@PathParam("idFile") String idFile) {
		File file = null;
		
		file = new File(SERVER_UPLOAD_LOCATION_FOLDER + idFile);
		/*
		if (!file.exists()){
			
		}
		*/
			 
		ResponseBuilder response = Response.ok((Object) file);
		response.header("Content-Disposition", "attachment; filename=" + file.getName());
		return response.build();
	}
	
	
	// ******* BDOC ***********************************************************
	
	/**
	 * Retorna un JSON con informacion de las firmas del documento BDOC
	 * @param bdocFile archivo BDOC a verificar
	 * @return JSON con informacion de las firmas del documento BDOC
	 */
	private JSONObject verifySignaturesInBdoc(String bdocFile) {
	
		JSONObject jsonSignatures = new JSONObject();

		JSONArray jsonSignaturesArray = new JSONArray();
		JSONArray jsonContainerValidationExceptionArray = new JSONArray();
		
		Security.addProvider(new BouncyCastleProvider());
		Container container;
		container = Container.open(bdocFile);
		
		int numberOfSignatures = container.getSignatures().size();
		if (numberOfSignatures == 0){
			jsonSignatures.put("signatureNumber", "0");
		}else{
			jsonSignatures.put("fileExist", "true");
			
			// informacion de archivos dentro del contenedor
			if (container.getDataFiles().size() > 0){
				jsonSignatures.put("numberOfDataFiles", container.getDataFiles().size()); 
				jsonSignatures.put("dataFiles", getJSONFromBDOCDataFiles(container.getDataFiles()));
				System.out.println(" dataFiles:  " + getJSONFromBDOCDataFiles(container.getDataFiles()).toString());
			}else{
				System.out.println(" dataFiles:  == 0");
			}

			
			jsonSignatures.put("numberOfSignatures", numberOfSignatures);
			
			ValidationResult validationResult = container.validate();
			List<DigiDoc4JException> exceptions = validationResult.getContainerErrors();
			
			boolean isDDoc = container.getDocumentType() == DocumentType.DDOC;
			
			if (exceptions.size() > 0){
				jsonSignatures.put("containerValidation", false);
				
				for (DigiDoc4JException exception : exceptions) {
					JSONObject containerException = new JSONObject();
					
					if (isDDoc && isWarning(((DDocContainer) container).getFormat(), exception)){
						System.out.println("    Warning: " + exception.toString());
						
				    }
				    else{
				    	System.out.println((isDDoc ? "  " : "   Error_: ") + exception.toString());
				    	
				    }
					containerException.put("containerValidationException", exception.toString());
				    jsonContainerValidationExceptionArray.put(containerException);
				}
			    if (isDDoc && (((ValidationResultForDDoc) validationResult).hasFatalErrors())) {
			    	jsonSignatures.put("validationResultForDDocHasFatalErrors", true);
			    	return jsonSignatures; 
			    }
			    jsonSignatures.put("containerValidationExceptions", jsonContainerValidationExceptionArray);
				
				
			}else{
				jsonSignatures.put("containerValidation", true);
				
				HashMap<String, String> signatureInformation;
				for (int i=0; i< numberOfSignatures; i++) {
					System.out.println("===== firma " + i + " =====");
					signatureInformation = verifyBDOCSignature(container.getSignature(i), container.getDocumentType());
					System.out.println("signatureInformation.size " + signatureInformation.size());
					
					JSONObject jo = getJSONFromASignature(signatureInformation);
					//System.out.println("jo:  " + jo.toString());
					jsonSignaturesArray.put(jo);					
				}
								
				jsonSignatures.put("signatures", jsonSignaturesArray);
								
				System.out.println(jsonSignatures.toString());				
			}
						
			
		}
		//verifyBdocContainer(container);		
		jsonSignatures.put("validation", "executed");				
		return jsonSignatures;
	}
	
	/**
	 * Retorna un JSON con informacion de los DataFiles incluidos en el contenedor
	 * @param dataFilesList lista de DataFile incluidos en el contenedor
	 * @return JSON con informacion de los DataFiles incluidos en el contenedor
	 */
	private JSONArray getJSONFromBDOCDataFiles(List<DataFile> dataFilesList) {
		JSONArray jsonDataFileArray = new JSONArray();
		
		for (int i = 0; i < dataFilesList.size(); i++){
			
			JSONObject tmpJsonDataFile = new JSONObject();
			DataFile df = dataFilesList.get(i);
			tmpJsonDataFile.put("dataFileSize", Long.toString(df.getFileSize()));
			tmpJsonDataFile.put("filename", df.getId());
			tmpJsonDataFile.put("mediaType", df.getMediaType());
			tmpJsonDataFile.put("name", df.getName());
			jsonDataFileArray.put(tmpJsonDataFile);
		}
		
		//JSONObject jsonDataFile = new JSONObject();
		//jsonDataFile.put("dataFiles", jsonDataFileArray);
		
		//return jsonDataFile;
		return jsonDataFileArray;
	}

	/**
	 * Retorna Hashmap con la informacion de una firma electronica que se verifica
	 * @param signature firma para verificar
	 * @param documentType tipo de documento 
	 * @return Hashmap con la informacion de una firma electronica que se verifica
	 */
	private static HashMap<String, String> verifyBDOCSignature(Signature signature, DocumentType documentType) {
		
		HashMap<String, String> signatureMap = new HashMap<String, String>();
		
		boolean isDDoc = documentType == DocumentType.DDOC;
		
		List<DigiDoc4JException> signatureValidationResult = signature.validate();
		
		if (signatureValidationResult.size() > 0) {
			System.out.println(ANSI_RED + "Signature " + signature.getId() + " is not valid" + ANSI_RESET);
	        signatureMap.put("isValid", Boolean.toString(false));
	        int counter = 1;
	        
	        //JSONArray jsonValidationExceptionArray = new JSONArray();
	        //JSONObject tmpValidationException = new JSONObject();
	        
	        for (DigiDoc4JException exception : signatureValidationResult) {
	          System.out.println((isDDoc ? "        " : "   Error: ") + exception.toString());
	          signatureMap.put("signature"+signature.getId()+"ValidationException"+counter, exception.toString());
	          
	          //tmpValidationException.put("ValidationException", exception.toString());	          
	          //jsonValidationExceptionArray.put(tmpValidationException);
	        }
	        //signatureMap.put("validationException", jsonValidationExceptionArray);
	      
	      if (isDDoc && isDDocTestSignature(signature)) {
	        System.out.println("Signature " + signature.getId() + " is a test signature");
	        signatureMap.put("isDDocTestSignature", Boolean.toString(true));
	      }
		}
		else{
			
			System.out.println("Signature " + signature.getId() + " is valid");
	    	signatureMap.put("isValid", Boolean.toString(true));
		}
		signatureMap.put("signatureId", signature.getId());
    	signatureMap.put("signatureProfile", signature.getProfile().toString());
    	signatureMap.put("signatureMethod", signature.getSignatureMethod());
    	/*
    	if (signature.getSignerRoles().size() > 0){	    	
    		signatureMap.put("signerRole1", signature.getSignerRoles().get(0));
    		if (signature.getSignerRoles().size() == 2){
    			signatureMap.put("signerRole2", signature.getSignerRoles().get(1));
    		}
    	}
    	*/
    	signatureMap.put("signatureCity", signature.getCity());
    	signatureMap.put("signatureState", signature.getStateOrProvince());
    	signatureMap.put("signaturePostalCode", signature.getPostalCode());
    	signatureMap.put("signatureCountry", signature.getCountryName());
    	signatureMap.put("signatureSigningTime", signature.getSigningTime().toString());
    	//signatureMap.put("signaturePolicy", signature.getPolicy());
    	//signatureMap.put("signatureOCSPProducedAtTimestamp", signature.getProducedAt().toString());
    	//signatureMap.put("signaturePolicyURI", signature.getSignaturePolicyURI().toString());
    	//signatureMap.put("signatureTimestampGenerationTime", signature.getTimeStampCreationTime().toString());
		
    	
    	X509Cert signerCertificate = signature.getSigningCertificate();
    	signatureMap.put("signerCertificateSerial", signerCertificate.getSerial());
    	signatureMap.put("signerCertificateSubjectName", signerCertificate.getSubjectName());
    	signatureMap.put("signerCertificateIssuer", signerCertificate.issuerName());
    	if (signerCertificate.isValid()){
    		signatureMap.put("signerCertificateIsValid", Boolean.toString(true));
    	}else{
    		signatureMap.put("signerCertificateIsValid", Boolean.toString(false));
    	}
    	
    	
    	
		return signatureMap;
	}
	
	
	private static void verifyBdocContainer(Container container) {
	    ValidationResult validationResult = container.validate();

	    List<DigiDoc4JException> exceptions = validationResult.getContainerErrors();
	    boolean isDDoc = container.getDocumentType() == DocumentType.DDOC;
	    for (DigiDoc4JException exception : exceptions) {
	      if (isDDoc && isWarning(((DDocContainer) container).getFormat(), exception))
	        System.out.println("    Warning: " + exception.toString());
	      else
	        System.out.println((isDDoc ? "  " : "   Error_: ") + exception.toString());
	    }

	    if (isDDoc && (((ValidationResultForDDoc) validationResult).hasFatalErrors())) {
	      return;
	    }

	    List<Signature> signatures = container.getSignatures();
	    if (signatures == null) {
	      throw new SignatureNotFoundException();
	    }

	    for (Signature signature : signatures) {
	      List<DigiDoc4JException> signatureValidationResult = signature.validate();
	      if (signatureValidationResult.size() == 0) {
	        System.out.println("Signature " + signature.getId() + " is valid");
	      } else {
	        System.out.println(ANSI_RED + "Signature " + signature.getId() + " is not valid" + ANSI_RESET);
	        for (DigiDoc4JException exception : signatureValidationResult) {
	          System.out.println((isDDoc ? "        " : "   Error: ")
	              + exception.toString());
	        }
	      }
	      if (isDDoc && isDDocTestSignature(signature)) {
	        System.out.println("Signature " + signature.getId() + " is a test signature");
	      }
	    }

	    showWarnings(validationResult);
	    verboseMessage(validationResult.getReport());
	 }

	 private static void showWarnings(ValidationResult validationResult) {
		 if (bdocWarnings) {
			 for (DigiDoc4JException warning : validationResult.getWarnings()) {
				 System.out.println("Warning: " + warning.toString());
		     }
		 }
	 }
	 
	 /**
	   * Checks is DigiDoc4JException predefined as warning for DDOC
	   *
	   * @param documentFormat format SignedDoc
	   * @param exception      error to check
	   * @return is this exception warning for DDOC utility program
	   * @see SignedDoc
	   */
	  public static boolean isWarning(String documentFormat, DigiDoc4JException exception) {
	    int errorCode = exception.getErrorCode();
	    return (errorCode == DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH
	        || errorCode == DigiDocException.ERR_OLD_VER
	        || errorCode == DigiDocException.ERR_TEST_SIGNATURE
	        || errorCode == DigiDocException.WARN_WEAK_DIGEST
	        || (errorCode == DigiDocException.ERR_ISSUER_XMLNS && !documentFormat.equals(SignedDoc.FORMAT_SK_XML)));
	  }

	  private static boolean isDDocTestSignature(Signature signature) {
		  CertValue certValue = ((DDocSignature) signature).getCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
		  if (certValue != null) {
			  if (DigiDocGenFactory.isTestCard(certValue.getCert())) return true;
		  }
		  return false;
	  }
	 
	  private static void verboseMessage(String message) {
		    if (bdocVerboseMode)
		      System.out.println(message);
	  }

	
	
	/**
	 * Verifica si un archivo posee firmas electronicas y retorna informacion
	 * de las mismas en un json
	 * @param idFile
	 * @return
	 */
	@GET
	@Path("/verificar/{idFile}")
	//@Produces("application/json")
	@Produces("text/plain")
	public String verifyFile(@PathParam("idFile") String idFile) {
		
		String file = SERVER_UPLOAD_LOCATION_FOLDER + idFile;
	
		//return getMimeType(file);
		
				
		File tmpFile = new File(file);
		String result = "";

		
		
		
		if (tmpFile.exists()) {
			result = "El archivo existe.";
			
			try {
				PdfReader reader = new PdfReader(file);
				AcroFields af = reader.getAcroFields();
				ArrayList<String> names = af.getSignatureNames();
				if (names.size() > 0) {
					result = "el archivo PDF posee "+ names.size() +" firma(s).\n";
					
					// sin esto explota: se debe agregar una implementacion del provider en tiempo de ejecucion
					//http://www.cs.berkeley.edu/~jonah/bc/org/bouncycastle/jce/provider/BouncyCastleProvider.html
					Security.addProvider(new BouncyCastleProvider());
					
					for (String name: names) {
						result = result +"Nombre de la firma: "+ name + "\n";
						System.out.println("Nombre de la firma: "+ name);
						
						PdfPKCS7 pk = af.verifySignature(name);
						
						Certificate[] pkc = pk.getCertificates();
						
						String tmpSignerName = pk.getSigningCertificate().getSubjectX500Principal().toString();
						
						
						result = result + "Sujeto del certificado firmante: " + tmpSignerName + "\n"; 
						//pk.getSigningCertificate().getSubjectX500Principal().getName() + "\n";
						System.out.println("Sujeto del certificado firmante: " + 
								pk.getSigningCertificate().getSubjectX500Principal().toString());
						  
						Calendar cal = pk.getSignDate();
						
						SimpleDateFormat date_format = new SimpleDateFormat("dd/MM/yyyy hh:mm:ss");
						
						//result = result + "Fecha de la firma: " + cal.toString() + "\n";
						result = result + "Fecha de la firma: " + date_format.format(cal.getTime()) + "\n";
						
						/*
						System.out.println("año: "+ cal.get(Calendar.YEAR));
						System.out.println("mes: "+ (cal.get(Calendar.MONTH) + 1));
						System.out.println("día: "+ cal.get(Calendar.DAY_OF_MONTH));
						System.out.println("hora: "+ cal.get(Calendar.HOUR));
						System.out.println("minuto: "+ cal.get(Calendar.MINUTE));
						System.out.println("segundo: "+ cal.get(Calendar.SECOND));
						*/
						//SimpleDateFormat date_format = new SimpleDateFormat("dd/MM/yyyy hh:mm:ss");
					    System.out.println(date_format.format(cal.getTime()));

					}
					
					
				}else{
					result = "el archivo PDF no posee firmas";
				}
				
				
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
		}else {
			result = "El archivo NO existe.";
		}
		
		
		return result;
		
		
	}
	
	/**
	 * Ejecuta el proceso de presign o preparacion de firma de documento pdf
	 * @param presignPar
	 * @param req objeto request para crear una sesion y mantener elementos del 
	 * pdf en la misma
	 * @param resp
	 */
	@POST
	@Path("/prepararfirmapdf")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	//public Response presign(PresignParameters presignPar, @Context HttpServletRequest req) {
	public PresignHash presign(PresignParameters presignPar, @Context HttpServletRequest req) {
		

		// cadena resultado de la funcion
		String result = "";
		
		PresignHash presignHash = new PresignHash();
		
		
		// cadena con el certificado
		String certHex = presignPar.getCertificate();
		System.out.println("certificado en Hex: " + certHex);
		
		// obtener el id del archivo 
		String fileId = presignPar.getFileId();
				
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			Certificate[] chain = new Certificate[1];
			
			InputStream in = new ByteArrayInputStream(hexStringToByteArray(certHex));
			chain[0] = factory.generateCertificate(in);
			
			if (chain[0] == null) {
				System.out.println("error chain[0] == null");
			}else {
				
				System.out.println("se cargo el certificado correctamente");
				System.out.println(chain[0].toString());
			}
			
			//String pdf = SERVER_UPLOAD_LOCATION_FOLDER + "e27a6a90-f955-4191-8e54-580e316a999d";
			String pdf = SERVER_UPLOAD_LOCATION_FOLDER + fileId;
			System.out.println("archivo a firmar: " + pdf);
			
			PdfReader reader = new PdfReader(pdf);
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			
			//FileOutputStream baos = new FileOutputStream(pdf+"-signed.pdf");
			
			PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');
			
			// crear la apariencia de la firma
	    	PdfSignatureAppearance sap = stamper.getSignatureAppearance();
	    	sap.setReason("Prueba de firma en dos partes");
	    	sap.setLocation("Merida, Venezuela");
	    	sap.setVisibleSignature(new Rectangle(36, 748, 144,780),1, "sig");
	    	sap.setCertificate(chain[0]);
	    	
	    	// crear la estructura de la firma
	    	PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
	    	dic.setReason(sap.getReason());
	    	dic.setLocation(sap.getLocation());
	    	dic.setContact(sap.getContact());
	    	dic.setDate(new PdfDate(sap.getSignDate()));
	    	
	    	sap.setCryptoDictionary(dic);
	    	
	    	HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer> ();
	    	exc.put(PdfName.CONTENTS, new Integer(8192 * 2 + 2));
	    	sap.preClose(exc);
	    	
	    	ExternalDigest externalDigest = new ExternalDigest() {
	    		public MessageDigest getMessageDigest(String hashAlgorithm)
	    		throws GeneralSecurityException {
	    			return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
	    		}
	    	};
			
			
	    	PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", null, externalDigest, false);
	    	
	    	InputStream data = sap.getRangeStream();
	    	
	    	byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));
	    	
	    	Calendar cal = Calendar.getInstance();
	    	byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, null, null, CryptoStandard.CMS);
	    	
	    	sh = DigestAlgorithms.digest(new ByteArrayInputStream(sh), externalDigest.getMessageDigest("SHA256"));
	    	
	    	System.out.println("sh length: "+ sh.length);
	    	    	
	    	String hashToSign = byteArrayToHexString(sh);
	    	System.out.println("***************************************************************");
	    	System.out.println("HASH EN HEXADECIMAL:");
	    	System.out.println(hashToSign);
	    	System.out.println("length: " +hashToSign.length());	
	    	System.out.println("***************************************************************");
			
	    	DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date date = new Date();
			System.out.println(dateFormat.format(date));
			//String d = dateFormat.format(date);
			
			
			// almacenar los objetos necesarios para realizar el postsign en una sesion
			HttpSession session = req.getSession(true);
			session.setAttribute("hashToSign", hashToSign);
			
			session.setAttribute("stamper", stamper);
			session.setAttribute("sgn", sgn);
			session.setAttribute("hash", hash);
			session.setAttribute("cal", cal);
			session.setAttribute("sap", sap);
			session.setAttribute("baos", baos);
			session.setAttribute("fileId", fileId);
			
			// creacion del json
			JSONObject jsonHash = new JSONObject();
			jsonHash.put("hashToSign", hashToSign);
			
			result = jsonHash.toString();
			
			presignHash.setHash(hashToSign);
				
			
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DocumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//return Response.status(200).entity(result).build();
		return presignHash;
			
	}
	
	
	/**
	 * Ejecuta el proceso de postsign o completacion de firma de documento pdf
	 * @param postsignPar
	 * @param req objeto request para crear una sesion y mantener elementos del 
	 * pdf en la misma
	 * @param resp
	 * @throws IOException 
	 */
	@POST
	@Path("/completarfirmapdf")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response postsign(PostsignParameters postsignPar, @Context HttpServletRequest req) throws IOException {
		
		
		// cadena resultado de la funcion
		String result = "";
				
		// cadena con la firma
		String signature = postsignPar.getSignature();
		System.out.println("firma en Hex: " + signature);
		
		HttpSession session = req.getSession(false);
		
		String fileId = (String) session.getAttribute("fileId");
		System.out.println("fileId: " + fileId);
		
		PdfStamper stamper = (PdfStamper) session.getAttribute("stamper");
		
		PdfPKCS7 sgn = (PdfPKCS7) session.getAttribute("sgn");
		
		byte[] hash = (byte[]) session.getAttribute("hash");
		
		Calendar cal = (Calendar) session.getAttribute("cal");
		
		PdfSignatureAppearance sap = (PdfSignatureAppearance) session.getAttribute("sap");
		
		ByteArrayOutputStream os = (ByteArrayOutputStream) session.getAttribute("baos");
		
		if (sgn == null) {
			System.out.println("sgn == null");
		}
		if (hash == null) {
			System.out.println("hash == null");
		}
		if (cal == null) {
			System.out.println("cal == null");
		}
		if (sap == null) {
			System.out.println("sap == null");
		}
		if (os == null) {
			System.out.println("os == null");
		}
		
		
		
		// convertir signature en bytes		
		byte[] signatureInBytes = hexStringToByteArray(signature);
				
		// completar el proceso de firma
		sgn.setExternalDigest(signatureInBytes, null, "RSA");
		byte[] encodeSig = sgn.getEncodedPKCS7(hash, cal, null, null, null, CryptoStandard.CMS);
		byte[] paddedSig = new byte[8192];
		System.arraycopy(encodeSig, 0, paddedSig, 0, encodeSig.length);
		PdfDictionary dic2 = new PdfDictionary();
		dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
		try {
			sap.close(dic2);
			
			stamper.close();
			System.out.println("stamper.close");
			
		}catch(DocumentException e) {
			
			System.out.println("throw new IOException");
			throw new IOException(e);
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("IOException e");
			e.printStackTrace();
			
		}
		
		String signedPdf = SERVER_UPLOAD_LOCATION_FOLDER + fileId + "-signed.pdf";
		
		FileOutputStream signedFile = new FileOutputStream(signedPdf);
		
		os.writeTo(signedFile);
		os.flush();
		
		
		
		// en este punto el archivo pdf debe estar disponible en la ruta
		// SERVER_UPLOAD_LOCATION_FOLDER + fileId;
		
		// llamar a una funcion que permita descargar el archivo
		
		result = "Archivo firmado correctamente";
		System.out.println("Archivo firmado correctamente");
		
		return Response.status(200).entity(result).build();
	}
	
	/**
	 * Ejecuta el proceso de presign o preparacion de firma de documento en formato BDOC
	 * 
	 * @param presignPar
	 * @param req
	 * @return
	 */
	@POST
	@Path("/bdoc/")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public PresignHash presignBdoc(PresignParameters presignPar, @Context HttpServletRequest req) {
		
		System.out.println("presignBdoc: ");
		
		
		String fileId;
		String certHex;
		
		CertificateFactory cf;
		X509Certificate signerCert;
		
		// cadena resultado de la funcion
		String result = "";
				
		PresignHash presignHash = new PresignHash();
		
		SignedInfo signedInfo;
		
		fileId = presignPar.getFileId();
		String sourceFile = SERVER_UPLOAD_LOCATION_FOLDER + fileId;
		
		certHex = presignPar.getCertificate();
		System.out.println("certificado en Hex: " + certHex);
		
//		try {
			/*		
			Configuration configuration = new Configuration(Configuration.Mode.TEST);
			
			configuration.loadConfiguration("/home/aaraujo/desarrollo/2015/workspace-luna/JAXRS-Murachi/WebContent/WEB-INF/lib/digidoc4j.yaml");
			configuration.setTslLocation("http://localhost/trusted-test-mp.xml");
		    
			Container container = Container.create(configuration);
		    SignatureParameters signatureParameters = new SignatureParameters();
		    SignatureProductionPlace productionPlace = new SignatureProductionPlace();
		    productionPlace.setCity("Merida");
		    signatureParameters.setProductionPlace(productionPlace);
		    signatureParameters.setRoles(asList("Desarrollador"));
		    container.setSignatureParameters(signatureParameters);
		    container.setSignatureProfile(SignatureProfile.B_BES);
		    container.addDataFile("/tmp/215d6ef7-d639-4191-87a1-ef68a91b2b27", "text/plain");
		    container.sign(new PKCS12Signer("/tmp/JuanHilario.p12", "123456".toCharArray()));
//		    Container container = Container.open("util/faulty/bdoc21-bad-nonce-content.bdoc");
		    container.save("/tmp/signed.bdoc");
		    ValidationResult results = container.validate();
		    System.out.println(results.getReport());
			*/

			
		Security.addProvider(new BouncyCastleProvider());
			System.setProperty("digidoc4j.mode", "TEST");
			
			Configuration configuration;
			configuration = new Configuration(Configuration.Mode.TEST);
			//configuration.loadConfiguration("/home/aaraujo/desarrollo/2015/workspace-luna/JAXRS-Murachi/WebContent/WEB-INF/lib/digidoc4j.yaml");
			
			//configuration.setTslLocation("https://tibisay.cenditel.gob.ve/murachi/raw-attachment/wiki/WikiStart/trusted-test-mp.xml");
			configuration.setTslLocation("http://localhost/trusted-test-mp.xml");
			
			Container container;
			
			container = Container.create(Container.DocumentType.BDOC, configuration);
			
			SignatureParameters signatureParameters = new SignatureParameters();
		    SignatureProductionPlace productionPlace = new SignatureProductionPlace();
		    productionPlace.setCity("Merida");
		    signatureParameters.setProductionPlace(productionPlace);
		    signatureParameters.setRoles(asList("Desarrollador"));
		    container.setSignatureParameters(signatureParameters);
		    container.setSignatureProfile(SignatureProfile.B_BES);
			
			container.addDataFile(sourceFile, "text/plain");
			
			container.sign(new PKCS12Signer("/tmp/JuanHilario.p12", "123456".toCharArray()));
		    container.save("/tmp/signed.bdoc");
		    ValidationResult results = container.validate();
		    System.out.println(results.getReport());
			
			/*
			cf = CertificateFactory.getInstance("X.509");
		
			InputStream in = new ByteArrayInputStream(hexStringToByteArray(certHex));
			
			signerCert = (X509Certificate) cf.generateCertificate(in);
			
			signedInfo = container.prepareSigning(signerCert);
			
			String hashToSign = byteArrayToHexString(signedInfo.getDigest());
			//System.out.println("presignBdoc - hash: " + byteArrayToHexString(signedInfo.getDigest()));
			System.out.println("presignBdoc - hash: " + hashToSign);
			
			
			//container.save("/tmp/containerTmp.bdoc");
			serialize(container, "/tmp/containerSerialized");
			*/
			
			String hashToSign = "firma exitosa";
			
			// creacion del json
			JSONObject jsonHash = new JSONObject();
			jsonHash.put("hashToSign", hashToSign);
						
			result = jsonHash.toString();
						
			presignHash.setHash(hashToSign);
			
			
/*			
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
*/		
		
		return presignHash;
		
	}
	
	
	@GET
	@Path("/testbdoc/")
	public String testBdoc() {
		
		Security.addProvider(new BouncyCastleProvider());
		
		Configuration configuration = new Configuration(Configuration.Mode.TEST);
		
		configuration.loadConfiguration("/home/aaraujo/desarrollo/2015/workspace-luna/JAXRS-Murachi/WebContent/WEB-INF/lib/digidoc4j.yaml");
		configuration.setTslLocation("http://localhost/trusted-test-mp.xml");
		
	    Container container = Container.create(configuration);
	    SignatureParameters signatureParameters = new SignatureParameters();
	    SignatureProductionPlace productionPlace = new SignatureProductionPlace();
	    productionPlace.setCity("Merida");
	    signatureParameters.setProductionPlace(productionPlace);
	    signatureParameters.setRoles(asList("Desarrollador"));
	    container.setSignatureParameters(signatureParameters);
	    container.setSignatureProfile(SignatureProfile.B_BES);
	    container.addDataFile("/tmp/01311213-5756-4707-a73d-6d42b09b26fd", "text/plain");
	    container.sign(new PKCS12Signer("/tmp/JuanHilario.p12", "123456".toCharArray()));
//	    Container container = Container.open("util/faulty/bdoc21-bad-nonce-content.bdoc");
	    container.save("/tmp/signed.bdoc");
	    ValidationResult result = container.validate();
	    System.out.println(result.getReport());
		
		return "test";
	}
	
	
	
	
	
	/**
	 * Prueba de ejecucion de programa desde consola. Incompleta
	 * @return
	 * @throws InterruptedException
	 */
	@GET
	@Path("/ejecutar")
	@Produces("text/plain")
	public String executeProcess() throws InterruptedException {
		
		
		String line = "";
		OutputStream stdin = null;
		InputStream stderr = null;
		InputStream stdout = null;
		
		try {
			System.out.print("...a crear el proceso");
			Process process = Runtime.getRuntime().exec("/usr/java/jdk1.7.0_21/bin/java -jar /home/aaraujo/desarrollo/2015/servicioVerificacion/testsigningpdf/holamundopdf.jar /tmp/589750.pdf /tmp/simonDiaz.pem /tmp/firmadoconsola.pdf");
			//Process process = Runtime.getRuntime().exec("ls -l");
			stdin = process.getOutputStream();
			stderr = process.getErrorStream();
			stdout = process.getInputStream();
			
			InputStreamReader isr = new InputStreamReader(stdout);
			BufferedReader buff = new BufferedReader (isr);

			
			while((line = buff.readLine()) != null)
				System.out.print(line+"\n");
			int exitValue = process.waitFor();
			if (exitValue != 0) {
			    System.out.println("Abnormal process termination");
			}	
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.print("...saliendo");
		return line;
	}
	
	
	
	
	
	/**
	 * 
	 * @param certHex
	 * @param httpHeaders
	 * @param req
	 * @param resp
	 */
	@POST
	@Path("/presignOld")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	public void presignOld(
			@FormParam("certHexInForm") String certHex,
			@Context HttpHeaders httpHeaders,
			@Context HttpServletRequest req,
			@Context HttpServletResponse resp) {
		

		String host = httpHeaders.getRequestHeader("host").get(0);
		
		String agent = httpHeaders.getRequestHeader("user-agent").get(0);
		String salida = "User agent :"+ agent +" from host : "+host;
		System.out.println(host);
		System.out.println(agent);
		System.out.println(salida);
		
		System.out.println("certificado en Hex: " + certHex);
		
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			Certificate[] chain = new Certificate[1];
			
			InputStream in = new ByteArrayInputStream(hexStringToByteArray(certHex));
			chain[0] = factory.generateCertificate(in);
			
			if (chain[0] == null) {
				System.out.println("error chain[0] == null");
			}else {
				
				System.out.println("se cargo el certificado correctamente");
				System.out.println(chain[0].toString());
			}
			
			String pdf = SERVER_UPLOAD_LOCATION_FOLDER + "e27a6a90-f955-4191-8e54-580e316a999d";
			
			PdfReader reader = new PdfReader(pdf);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');
			
			// crear la apariencia de la firma
	    	PdfSignatureAppearance sap = stamper.getSignatureAppearance();
	    	sap.setReason("Prueba de firma en dos partes");
	    	sap.setLocation("Merida, Venezuela");
	    	sap.setVisibleSignature(new Rectangle(36, 748, 144,780),1, "sig");
	    	sap.setCertificate(chain[0]);
	    	
	    	// crear la estructura de la firma
	    	PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
	    	dic.setReason(sap.getReason());
	    	dic.setLocation(sap.getLocation());
	    	dic.setContact(sap.getContact());
	    	dic.setDate(new PdfDate(sap.getSignDate()));
	    	
	    	sap.setCryptoDictionary(dic);
	    	
	    	HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer> ();
	    	exc.put(PdfName.CONTENTS, new Integer(8192 * 2 + 2));
	    	sap.preClose(exc);
	    	
	    	ExternalDigest externalDigest = new ExternalDigest() {
	    		public MessageDigest getMessageDigest(String hashAlgorithm)
	    		throws GeneralSecurityException {
	    			return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
	    		}
	    	};
			
			
	    	PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", null, externalDigest, false);
	    	
	    	InputStream data = sap.getRangeStream();
	    	
	    	byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));
	    	
	    	Calendar cal = Calendar.getInstance();
	    	byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, null, null, CryptoStandard.CMS);
	    	
	    	sh = DigestAlgorithms.digest(new ByteArrayInputStream(sh), externalDigest.getMessageDigest("SHA256"));
	    	
	    	System.out.println("sh length: "+ sh.length);
	    	    	
	    	String hashToSign = byteArrayToHexString(sh);
	    	System.out.println("***************************************************************");
	    	System.out.println("HASH EN HEXADECIMAL:");
	    	System.out.println(hashToSign);
	    	System.out.println("length: " +hashToSign.length());	
	    	System.out.println("***************************************************************");
			
	    	DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date date = new Date();
			System.out.println(dateFormat.format(date));
			String d = dateFormat.format(date);
			
			
			// almacenar los objetos necesarios para realizar el postsign en una sesion
			HttpSession session = req.getSession(true);
			session.setAttribute("hashToSign", hashToSign);
			
			session.setAttribute("sgn", sgn);
			session.setAttribute("hash", hash);
			session.setAttribute("cal", cal);
			session.setAttribute("sap", sap);
			session.setAttribute("baos", baos);
			
		
			
			resp.sendRedirect("http://localhost/murachi2.html");
			
			
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DocumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	
	}
	
	
	@POST
	@Path("/postsign")
	public String postsignOld(@Context HttpServletRequest req,
			@Context HttpServletResponse resp) {
		
		System.out.println("...postsign()...");
		
		HttpSession session = req.getSession(false);
		Object att = session.getAttribute("hashToSign");
				
	
		String output = "atributo leido de la sesion: " + att.toString();
		
		
		return output;
		//return Response.status(200).entity(output).build();
	}
	
	
	@GET
	@Path("/retornajson")
	@Produces(MediaType.APPLICATION_JSON)
	public PresignHash retornajson(@Context HttpServletRequest req) {
		
		
		
		PresignHash h = new PresignHash();
		h.setHash("ESTO SERIA UN HASH");
		
		System.out.println("...retornajson..."+ h.getHash());
		
		return h;
		
	}
	
	@POST
	@Path("/enviarjson")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public PresignHash recibejson( PresignParameters par) {
		
		String fileId = par.getFileId();
		System.out.println("...fileId recibido..."+ fileId);
		
		String cert = par.getCertificate();
		System.out.println("...certificate recibido..."+ cert);
		
		PresignHash h = new PresignHash();
		h.setHash("DEBES FIRMAR ESTO");
		
		System.out.println("...recibejson..."+ h.getHash());
		
		return h;
		
	}
	
	
	
	
	/**
	 * Retorna el mimeType del archivo pasado como argumento
	 * @param absolutFilePath ruta absoluta del archivo
	 * @return mimeType del archivo pasado como argumento
	 */
	public String getMimeType(String absolutFilePath) {
				
		String result = "";		
		java.nio.file.Path source = Paths.get(absolutFilePath);
		try {
			result = Files.probeContentType(source);			
			System.out.println(result);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		return result;		 
	}
	
	/**
	 * Convierte una cadena Hexadecimal en un arreglo de bytes
	 * @param s cadena hexadecimal
	 * @return arreglo de bytes resultantes de la conversion de la cadena hexadecimal
	 */
	public static byte[] hexStringToByteArray(String s) {
	    byte[] b = new byte[s.length() / 2];
	    for (int i = 0; i < b.length; i++) {
	      int index = i * 2;
	      int v = Integer.parseInt(s.substring(index, index + 2), 16);
	      b[i] = (byte) v;
	    }
	    return b;
	  }
	
	/**
	   * Converts a byte array into a hex string.
	   * @param byteArray the byte array source
	   * @return a hex string representing the byte array
	   */
	  public static String byteArrayToHexString(final byte[] byteArray) {
	      if (byteArray == null) {
	          return "";
	      }
	      return byteArrayToHexString(byteArray, 0, byteArray.length);
	  }
	  
	  public static String byteArrayToHexString(final byte[] byteArray, int startPos, int length) {
	      if (byteArray == null) {
	          return "";
	      }
	      if(byteArray.length < startPos+length){
	          throw new IllegalArgumentException("startPos("+startPos+")+length("+length+") > byteArray.length("+byteArray.length+")");
	      }
//	      int readBytes = byteArray.length;
	      StringBuilder hexData = new StringBuilder();
	      int onebyte;
	      for (int i = 0; i < length; i++) {
	          onebyte = ((0x000000ff & byteArray[startPos+i]) | 0xffffff00);
	          hexData.append(Integer.toHexString(onebyte).substring(6));
	      }
	      return hexData.toString();
	  }
	
	  /**
	   * Serializa el contenedor BDOC pasado como argumento
	   * @param container Contenedor que se desea serializar
	   * @param filePath ruta absoluta al archivo serializado
	   * @throws IOException
	   */
	  private static void serialize(Container container, String filePath) throws IOException {
		  FileOutputStream fileOut = new FileOutputStream(filePath+".bin");
		  ObjectOutputStream out = new ObjectOutputStream(fileOut);
		  out.writeObject(container);
		  out.flush();
		  out.close();
		  fileOut.close();
	  }
	  
	  /**
	   * Deserializa el contenedor BDOC pasado como argumento
	   * @param filePath ruta absoluta al contenedor que se desea deserializar
	   * @return contenedor deserializado
	   * @throws IOException
	   * @throws ClassNotFoundException
	   */
	  private static Container deserializer(String filePath) throws IOException, ClassNotFoundException {
		  //FileInputStream fileIn = new FileInputStream("container.bin");
		  FileInputStream fileIn = new FileInputStream(filePath);
		  ObjectInputStream in = new ObjectInputStream(fileIn);
		  Container container = (Container) in.readObject();
		  in.close();
		  fileIn.close();
		  return container;
	  }
	  
}
