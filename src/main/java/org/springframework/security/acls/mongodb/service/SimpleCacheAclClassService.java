package org.springframework.security.acls.mongodb.service;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.springframework.security.acls.mongodb.model.QAclClass;
import org.springframework.security.acls.mongodb.dao.AclClassRepository;
import org.springframework.security.acls.mongodb.exception.ObjectClassNotExistException;
import org.springframework.security.acls.mongodb.model.AclClass;


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
	public String getObjectClassName(String objectClassId) throws ObjectClassNotExistException {
		for (Entry<String, String> entry : classNameToIdMap.entrySet()) {
			if (entry.getValue().equals(objectClassId)) return entry.getKey();
		}
		AclClass aclClass = aclClassRepository.findOne(objectClassId);
		if (aclClass == null) throw new ObjectClassNotExistException(objectClassId);
		classNameToIdMap.put(aclClass.getClassName(), objectClassId);
		return aclClass.getClassName();
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
