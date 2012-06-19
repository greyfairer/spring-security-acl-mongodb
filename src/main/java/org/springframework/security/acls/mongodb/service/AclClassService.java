package org.springframework.security.acls.mongodb.service;

import org.springframework.security.acls.mongodb.exception.ObjectClassNotExistException;
import org.springframework.security.acls.mongodb.model.AclClass;

public interface AclClassService {
	String getObjectClassId(String objectClassName) throws ObjectClassNotExistException;
	String getObjectClassName(String objectClassId) throws ObjectClassNotExistException;
	AclClass createAclClass(AclClass aclClass);
}
