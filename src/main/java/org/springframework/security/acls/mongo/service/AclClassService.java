package org.springframework.security.acls.mongo.service;

import org.springframework.security.acls.mongo.model.AclClass;

public interface AclClassService {
	String getObjectClassId(String objectClassName);
	AclClass createAclClass(AclClass aclClass);
}
