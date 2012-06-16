package org.springframework.security.acls.mongo.exception;

public class ObjectClassNotExistException extends RuntimeException {

	private static final long serialVersionUID = 6093973902790409262L;

	public ObjectClassNotExistException(String objectClass) {
		super("The Object Class '" + objectClass + "' does not exist");
	}
}
