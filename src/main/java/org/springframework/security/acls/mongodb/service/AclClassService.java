package org.springframework.security.acls.mongodb.service;

import org.springframework.security.acls.mongodb.model.AclClass;

public interface AclClassService {
	String getObjectClassId(String objectClassName);
	String getObjectClassName(String objectClassId);
	AclClass createAclClass(AclClass aclClass);
}
