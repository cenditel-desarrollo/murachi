package ve.gob.cenditel.murachi;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

/**
 * Interfaz que mapea excepciones Java a objetos Response.
 * @author aaraujo
 *
 */
@Provider
public class MurachiExceptionHandler implements ExceptionMapper<MurachiException> 
{
	@Override
	public Response toResponse(MurachiException exception) 
	{
		return Response.status(Status.BAD_REQUEST).entity(exception.getMessage()).build();	
	}
}
