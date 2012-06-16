package org.springframework.security.acls.mongo.service;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.acls.mongo.dao.AclClassRepository;
import org.springframework.security.acls.mongo.exception.ObjectClassNotExistException;
import org.springframework.security.acls.mongo.model.AclClass;
import org.springframework.security.acls.mongo.model.QAclClass;


public class SimpleCacheAclClassService implements AclClassService {
	
	private Map<String, String> classNameToIdMap = new HashMap<String, String>();
	
	private AclClassRepository aclClassRepository;
	
	public SimpleCacheAclClassService(AclClassRepository aclClassRepository) {
		super();
		this.aclClassRepository = aclClassRepository;
	}

	@Override
	public String getObjectClassId(String objectClassName) throws ObjectClassNotExistException {
		String id = getFromCache(objectClassName);
		if (id != null) return id;
		id = getFromDatastore(objectClassName);
		if (id == null) throw new ObjectClassNotExistException(objectClassName);
		putInCache(objectClassName, id);
		return id;
	}
	
	@Override
	public AclClass createAclClass(AclClass aclClass) {
		return aclClassRepository.save(aclClass);
	}

	protected String getFromCache(String objectClassName) {
		return classNameToIdMap.get(objectClassName);
	}
	
	protected String getFromDatastore(String objectClassName) {
		QAclClass aclClass = QAclClass.aclClass;
		AclClass result = aclClassRepository.findOne(aclClass.className.eq(objectClassName));
		if (result == null) {
			return null;
		}
		return result.getId();
	}
	
	protected void putInCache(String className, String id) {
		classNameToIdMap.put(className, id);
	}
}
