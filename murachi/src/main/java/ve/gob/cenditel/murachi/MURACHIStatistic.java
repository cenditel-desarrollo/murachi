package ve.gob.cenditel.murachi;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.log4j.Logger;
 
/**
 * Clase para obtener estadisticas del servicio murachi.
 * 
 * @author aaraujo
 *
 */
public class MURACHIStatistic {
	
	private String databaseName;
	
	private String databaseHost;
	
	private String databasePort;
	
	private String databaseLogin;
	
	private String databasePassword;
	
	private String databaseConnection;
	
	final static Logger logger = Logger.getLogger(MURACHIStatistic.class);
	
	/**
	 * Constructor de la clase
	 * 
	 * @param dbLogin login para la conexion de base de datos
	 * @param dbPassword contrasena para la conexion de base de datos
	 * 
	 */
	MURACHIStatistic(String dbHost, String dbPort, String dbName, String dbLogin, String dbPassword) {
		databaseName = dbName;
		databaseHost = dbHost;
		databasePort = dbPort;
		databaseLogin = dbLogin;		
		databasePassword = dbPassword;		
		databaseConnection = "jdbc:postgresql://"+
				databaseHost +
				":" +
				databasePort +
				"/" +
				databaseName;
	}
	
	
	public void createDatabaseTables() throws InstantiationException, IllegalAccessException {
        Connection conn = null;
        Statement stmt = null;
        try {
            Class.forName("org.postgresql.Driver").newInstance();
            System.out.println("postgresql JDBC Driver Registered!");
 
            conn = DriverManager.getConnection(databaseConnection, databaseLogin, databasePassword);
            
            stmt = conn.createStatement();
            String sql = "CREATE TABLE SIGNATURES " +
                         "(SIGNATURE_ID SERIAL PRIMARY KEY NOT NULL," +
                         " TYPE           CHAR(4)    NOT NULL)";
            stmt.executeUpdate(sql);
            System.out.println("table SIGNATURES created!");
            
            stmt = conn.createStatement();
            
            sql = "CREATE TABLE VERIFICATIONS " +
                    "(VERIFICATION_ID SERIAL PRIMARY KEY NOT NULL,"+
            		"TYPE CHAR(4) NOT NULL)";
            stmt.executeUpdate(sql);                        
            System.out.println("table VERIFICATIONS created!");
            
            stmt = conn.createStatement();
            
            sql = "CREATE TABLE SIGNATURES_ERROR " +
                    "(SIGNATURE_ERROR_ID SERIAL PRIMARY KEY NOT NULL, "+
            		"TYPE CHAR(4) NOT NULL)";
            stmt.executeUpdate(sql);
            System.out.println("table SIGNATURE_ERROR created!");
            
            stmt.close();
            //conn.close();
            
            
        } catch (ClassNotFoundException e) {
            //Cannot register postgresql MySQL driver
            System.out.println("This is something you have not add in postgresql library to classpath!");
            e.printStackTrace();
        }catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        }finally{
            //After using connection, release the postgresql resource.
            try {
                conn.close();
            } catch (SQLException e) {
            	logger.error(e.getMessage());
            }
        }
    }
    
    /**
     * Incrementa en una unidad la cuenta de las firmas realizadas con el servicio
     * 
     * @param type tipo de firma: 0->PDF, 1->BDOC
     * 
     */
    public void incrementSignatures(int type) {
    	Connection c = null;
        Statement stmt = null;
        try {
           Class.forName("org.postgresql.Driver");
           
           //c = DriverManager.getConnection("jdbc:postgresql://localhost:5432/databasemurachi", databaseLogin, databasePassword);
           c = DriverManager.getConnection(databaseConnection, databaseLogin, databasePassword);
           
           c.setAutoCommit(false);
           //System.out.println("Opened database successfully");

           stmt = c.createStatement();
           String signatureType = "";
           
           if (type == 0) {
        	   signatureType = "pdf";
           }else if (type == 1){
        	   signatureType = "bdoc";
           }else{
        	   signatureType = "unknown";
           }
        	   
           String sql = "INSERT INTO SIGNATURES (TYPE) VALUES ('"+ signatureType +"');";
           stmt.executeUpdate(sql);
           stmt.close();
           c.commit();
           c.close();
        } catch (Exception e) {
        	logger.error(e.getClass().getName()+": "+ e.getMessage());
            System.err.println( e.getClass().getName()+": "+ e.getMessage() );
        }
        //System.out.println("Records created successfully");
    }
    
    /**
     * Incrementa en una unidad la cuenta de las firmas incompletas realizadas con el servicio
     * 
     * @param type tipo de firma: 0->PDF, 1->BDOC
     * 
     */
    public void incrementErrorSignatures(int type) {
    	Connection c = null;
        Statement stmt = null;
        try {
           Class.forName("org.postgresql.Driver");
           
           //c = DriverManager.getConnection("jdbc:postgresql://localhost:5432/databasemurachi", databaseLogin, databasePassword);
           c = DriverManager.getConnection(databaseConnection, databaseLogin, databasePassword);
           
           c.setAutoCommit(false);
           //System.out.println("Opened database successfully");

           stmt = c.createStatement();
           String signatureType = "";
           
           if (type == 0) {
        	   signatureType = "pdf";
           }else if (type == 1){
        	   signatureType = "bdoc";
           }else{
        	   signatureType = "unknown";
           }
        	   
           String sql = "INSERT INTO SIGNATURES_ERROR (TYPE) VALUES ('"+ signatureType +"');";
           stmt.executeUpdate(sql);
           stmt.close();
           c.commit();
           c.close();
        } catch (Exception e) {
        	logger.error(e.getClass().getName()+": "+ e.getMessage());
            System.err.println( e.getClass().getName()+": "+ e.getMessage() );
        }
        //System.out.println("Records created successfully");
    }
    
    
    /**
     * Incrementa en una unidad la cuenta de las verificaciones de firmas realizadas con el servicio
     * 
     * @param type tipo de firma: 0->PDF, 1->BDOC
     * 
     */
    public void incrementVerifications(int type) {
    	Connection c = null;
        Statement stmt = null;
        try {
           Class.forName("org.postgresql.Driver");
           
           //c = DriverManager.getConnection("jdbc:postgresql://localhost:5432/databasemurachi", databaseLogin, databasePassword);
           c = DriverManager.getConnection(databaseConnection, databaseLogin, databasePassword);
           
           c.setAutoCommit(false);
           //System.out.println("Opened database successfully");

           stmt = c.createStatement();
           String signatureType = "";
           
           if (type == 0) {
        	   signatureType = "pdf";
           }else if (type == 1){
        	   signatureType = "bdoc";
           }else{
        	   signatureType = "unkn";
           }
        	   
           String sql = "INSERT INTO VERIFICATIONS (TYPE) VALUES ('"+ signatureType +"');";
           stmt.executeUpdate(sql);
           stmt.close();
           c.commit();
           c.close();
        } catch (Exception e) {
        	logger.error(e.getClass().getName()+": "+ e.getMessage());
            System.err.println( e.getClass().getName()+": "+ e.getMessage() );
        }
        
    }
    
    
    
    /**
     * Retorna el número de firmas realizadas exitosamente con el servicio.
     * 
     * @return número de firmas realizadas exitosamente con el servicio.
     */
    public int countOfSigantures() {
    	
    	Connection c = null;
        Statement stmt = null;
        int rowCount = 0;
        
        try {
           Class.forName("org.postgresql.Driver");
           //c = DriverManager.getConnection("jdbc:postgresql://localhost:5432/databasemurachi", databaseLogin, databasePassword);
           c = DriverManager.getConnection(databaseConnection, databaseLogin, databasePassword);
           
           c.setAutoCommit(false);
           //System.out.println("Opened database successfully");

           stmt = c.createStatement();
           ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM SIGNATURES");
           // get the number of rows from the result set
           rs.next();
           rowCount = rs.getInt(1);
           //System.out.println(rowCount);
         
           stmt.close();
           c.commit();
           c.close();
        } catch (Exception e) {
        	logger.error(e.getClass().getName()+": "+ e.getMessage());
            System.err.println( e.getClass().getName()+": "+ e.getMessage() );
            rowCount = -1;
        }
        //System.out.println("Records created successfully");
    	    	
		return rowCount;    	
    }
    
    /**
     * Retorna el número de firmas que no se completaron en el servicio.
     * 
     * @return número de firmas que no se completaron en el servicio.
     */
    public int countOfSiganturesFailed() {
    	
    	Connection c = null;
        Statement stmt = null;
        int rowCount = 0;
        
        try {
           Class.forName("org.postgresql.Driver");
           //c = DriverManager.getConnection("jdbc:postgresql://localhost:5432/databasemurachi", databaseLogin, databasePassword);
           c = DriverManager.getConnection(databaseConnection, databaseLogin, databasePassword);
           
           c.setAutoCommit(false);
           //System.out.println("Opened database successfully");

           stmt = c.createStatement();
           ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM SIGNATURES_ERROR");
           // get the number of rows from the result set
           rs.next();
           rowCount = rs.getInt(1);
           //System.out.println(rowCount);
         
           stmt.close();
           c.commit();
           c.close();
        } catch (Exception e) {
        	logger.error(e.getClass().getName()+": "+ e.getMessage());
            System.err.println( e.getClass().getName()+": "+ e.getMessage() );
            rowCount = -1;
        }
        //System.out.println("Records created successfully");
    	    	
		return rowCount;    	
    }
 
    /**
     * Retorna el número de verificaciones de firma electrónica realizadas en el servicio
     * 
     * @return número de verificaciones de firma electrónica realizadas en el servicio
     */
    public int countOfVerifications() {
    	
    	Connection c = null;
        Statement stmt = null;
        int rowCount = 0;
        
        try {
           Class.forName("org.postgresql.Driver");
           //c = DriverManager.getConnection("jdbc:postgresql://localhost:5432/databasemurachi", databaseLogin, databasePassword);
           c = DriverManager.getConnection(databaseConnection, databaseLogin, databasePassword);
           
           c.setAutoCommit(false);
           //System.out.println("Opened database successfully");

           stmt = c.createStatement();
           ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM VERIFICATIONS");
           // get the number of rows from the result set
           rs.next();
           rowCount = rs.getInt(1);
           //System.out.println(rowCount);
         
           stmt.close();
           c.commit();
           c.close();
        } catch (Exception e) {
        	logger.error(e.getClass().getName()+": "+ e.getMessage());
            System.err.println( e.getClass().getName()+": "+ e.getMessage() );
            rowCount = -1;
        }
        //System.out.println("Records created successfully");
    	    	
		return rowCount;    	
    }
    
    
}