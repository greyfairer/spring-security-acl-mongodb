package org.springframework.security.acls.mongodb.service;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.springframework.security.acls.mongodb.dao.AclClassRepository;
import org.springframework.security.acls.mongodb.exception.ObjectClassAlreadyExistedException;
import org.springframework.security.acls.mongodb.model.AclClass;
import org.springframework.security.acls.mongodb.model.QAclClass;


public class SimpleCacheAclClassService implements AclClassService {
	
	private Map<String, String> classNameToIdMap = new HashMap<String, String>();
	
	private AclClassRepository aclClassRepository;
	
	public SimpleCacheAclClassService(AclClassRepository aclClassRepository) {
		super();
		this.aclClassRepository = aclClassRepository;
	}

	@Override
	public String getObjectClassId(String objectClassName) {
		String id = classNameToIdMap.get(objectClassName);
		if (id != null) return id;

		QAclClass aclClass = QAclClass.aclClass;
		AclClass result = aclClassRepository.findOne(aclClass.className.eq(objectClassName));
		if (result == null) return null;
		
		classNameToIdMap.put(objectClassName, result.getId());
		return result.getId();
	}
	
	@Override
	public String getObjectClassName(String objectClassId) {
		for (Entry<String, String> entry : classNameToIdMap.entrySet()) {
			if (entry.getValue().equals(objectClassId)) return entry.getKey();
		}
		AclClass aclClass = aclClassRepository.findOne(objectClassId);
		if (aclClass == null) return null;
		classNameToIdMap.put(aclClass.getClassName(), objectClassId);
		return aclClass.getClassName();
	}
	
	@Override
	public AclClass createAclClass(AclClass aclClass) {
		if (aclClass == null) {
			throw new IllegalArgumentException("aclClass must not be null");
		}
		
		if (aclClass.getClassName() == null || aclClass.getClassName().isEmpty()) {
			throw new IllegalArgumentException("aclClass must have a valid className");
		}
		
		QAclClass qAclClass = QAclClass.aclClass;
		AclClass result = aclClassRepository.findOne(qAclClass.className.eq(aclClass.getClassName()));
		if (result != null) {
			throw new ObjectClassAlreadyExistedException(aclClass.getClassName());
		}
		
		return aclClassRepository.save(aclClass);
	}
}
