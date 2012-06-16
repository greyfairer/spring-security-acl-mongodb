package org.springframework.security.acls.mongodb.service;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.acls.mongodb.model.QAclClass;
import org.springframework.security.acls.mongodb.dao.AclClassRepository;
import org.springframework.security.acls.mongodb.exception.ObjectClassNotExistException;
import org.springframework.security.acls.mongodb.model.AclClass;
import org.springframework.security.acls.mongodb.service.SimpleCacheAclClassService;

@RunWith(MockitoJUnitRunner.class)
public class SimpleCacheAclClassServiceTest {
	
	@Mock
	private AclClassRepository mockRepository;

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void getObjectClassId_NewObjectClassName_ShouldRetrieveFromDataStore() {
		// arrange
		final String STUBBED_ACL_CLASS_ID = "fake-id";
		final String STUBBED_ACL_CLASS_NAME = "com.example.model.StubbedClass";
		
		AclClass stubbedAclClass = new AclClass();
		stubbedAclClass.setId(STUBBED_ACL_CLASS_ID);
		stubbedAclClass.setClassName(STUBBED_ACL_CLASS_NAME);
		QAclClass aclClass = QAclClass.aclClass;
		when(mockRepository.findOne(aclClass.className.eq(STUBBED_ACL_CLASS_NAME))).thenReturn(stubbedAclClass);
		
		// action
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		String objectClassId = cacheAclClassService.getObjectClassId(STUBBED_ACL_CLASS_NAME);
		
		// verify
		assertEquals("", STUBBED_ACL_CLASS_ID, objectClassId);
		verify(mockRepository).findOne(eq(aclClass.className.eq(STUBBED_ACL_CLASS_NAME)));
	}
	
	@Test(expected = ObjectClassNotExistException.class)
	public void getObjectClassId_ObjectClassNameDoesNotExist_ThrowException() throws Exception {
		// arrange 
		final String STUBBED_ACL_CLASS_NAME = "com.example.model.StubbedClass";
		
		// action
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		cacheAclClassService.getObjectClassId(STUBBED_ACL_CLASS_NAME);
		
		// verify
	}
	
	@Test
	public void getObjectClassId_SecondCallOnSameObjectClass_RetrieveFromCache() throws Exception {
		// arrange 
		final String STUBBED_ACL_CLASS_ID = "fake-id";
		final String STUBBED_ACL_CLASS_NAME = "com.example.model.StubbedClass";

		AclClass stubbedAclClass = new AclClass();
		stubbedAclClass.setId(STUBBED_ACL_CLASS_ID);
		stubbedAclClass.setClassName(STUBBED_ACL_CLASS_NAME);
		QAclClass aclClass = QAclClass.aclClass;
		when(mockRepository.findOne(aclClass.className.eq(STUBBED_ACL_CLASS_NAME))).thenReturn(stubbedAclClass);
		
		// action
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		String objectClassId1 = cacheAclClassService.getObjectClassId(STUBBED_ACL_CLASS_NAME);
		String objectClassId2 = cacheAclClassService.getObjectClassId(STUBBED_ACL_CLASS_NAME);
		
		// verify
		assertEquals(objectClassId1, STUBBED_ACL_CLASS_ID);
		assertEquals(objectClassId2, STUBBED_ACL_CLASS_ID);
		
		verify(mockRepository, times(1)).findOne(aclClass.className.eq(STUBBED_ACL_CLASS_NAME));
	}
}
