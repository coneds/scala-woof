package io.snyk.woof.server

import io.dropwizard.jersey.errors.ErrorMessage
import org.slf4j.LoggerFactory
import javax.ws.rs.core.MediaType
import javax.ws.rs.core.Response
import javax.ws.rs.ext.ExceptionMapper

class JsonExceptionMapper extends ExceptionMapper[Exception] {
  private val logger = LoggerFactory.getLogger(classOf[JsonExceptionMapper])

  override def toResponse(exception: Exception): Response = {
    // Log the full exception details server-side for debugging
    logger.error("Internal server error occurred", exception)
    
    // Return a generic error message to the client to prevent information disclosure
    val genericErrorMessage = "An internal server error occurred. Please try again later."
    Response.status(Response.Status.INTERNAL_SERVER_ERROR)
      .`type`(MediaType.APPLICATION_JSON_TYPE)
      .entity(new ErrorMessage(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode, genericErrorMessage))
      .build
  }
}
