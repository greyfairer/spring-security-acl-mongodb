package org.springframework.security.acls.mongodb.exception;

public class ObjectClassAlreadyExistedException extends RuntimeException {

	private static final long serialVersionUID = -4924257766852874773L;

	public ObjectClassAlreadyExistedException(String objectClass) {
		super("The Object Class '" + objectClass + "' have already existed in the system");
	}
}
