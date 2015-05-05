package ve.gob.cenditel.murachi;

import java.io.Serializable;

/**
 * Clase que abstrae una excepcion del servicio Murachi
 * @author aaraujo
 *
 */
public class MurachiException extends Exception implements Serializable
{
	private static final long serialVersionUID = 1L;

	public MurachiException()
	{
		super();
	}
	
	public MurachiException(String msg)
	{
		super(msg);
	}
	
	public MurachiException(String msg, Exception e)
	{
		super(msg, e);
	}
}
