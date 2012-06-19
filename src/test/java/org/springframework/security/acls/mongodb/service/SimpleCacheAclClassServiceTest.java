package org.springframework.security.acls.mongodb.service;

import static org.junit.Assert.*;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.acls.mongodb.dao.AclClassRepository;
import org.springframework.security.acls.mongodb.exception.ObjectClassAlreadyExistedException;
import org.springframework.security.acls.mongodb.exception.ObjectClassNotExistException;
import org.springframework.security.acls.mongodb.model.AclClass;
import org.springframework.security.acls.mongodb.model.QAclClass;
import org.springframework.security.util.FieldUtils;

import com.mysema.query.types.Predicate;

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
	@SuppressWarnings("unchecked")
	public void getObjectClassId_NewObjectClassName_ShouldRetrieveFromDataStoreAndPutIntoCache() throws Exception {
		// arrange
		final String STUBBED_ACL_CLASS_ID = "fake-id";
		final String STUBBED_ACL_CLASS_NAME = "com.example.model.StubbedClass";
		
		AclClass stubbedAclClass = new AclClass();
		stubbedAclClass.setId(STUBBED_ACL_CLASS_ID);
		stubbedAclClass.setClassName(STUBBED_ACL_CLASS_NAME);
		QAclClass aclClass = QAclClass.aclClass;
		when(mockRepository.findOne(aclClass.className.eq(STUBBED_ACL_CLASS_NAME))).thenReturn(stubbedAclClass);
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		
		// action
		String objectClassId = cacheAclClassService.getObjectClassId(STUBBED_ACL_CLASS_NAME);
		
		// verify
		assertEquals("", STUBBED_ACL_CLASS_ID, objectClassId);
		Map<String, String> cache = (Map<String, String>) FieldUtils.getFieldValue(cacheAclClassService, "classNameToIdMap");
		assertTrue(cache.containsKey(STUBBED_ACL_CLASS_NAME));
		assertTrue(cache.containsValue(STUBBED_ACL_CLASS_ID));
		verify(mockRepository).findOne(eq(aclClass.className.eq(STUBBED_ACL_CLASS_NAME)));
	}
	
	@Test(expected = ObjectClassNotExistException.class)
	public void getObjectClassId_ObjectClassNameDoesNotExist_ThrowException() throws Exception {
		// arrange 
		final String STUBBED_ACL_CLASS_NAME = "com.example.model.StubbedClass";
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		
		// action
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
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		
		// action
		String objectClassId1 = cacheAclClassService.getObjectClassId(STUBBED_ACL_CLASS_NAME);
		String objectClassId2 = cacheAclClassService.getObjectClassId(STUBBED_ACL_CLASS_NAME);
		
		// verify
		assertEquals(objectClassId1, STUBBED_ACL_CLASS_ID);
		assertEquals(objectClassId2, STUBBED_ACL_CLASS_ID);
		
		verify(mockRepository, times(1)).findOne(aclClass.className.eq(STUBBED_ACL_CLASS_NAME));
	}
	
	@Test
	public void createAclClass_ValidClassName_PersistedInDatastore() throws Exception {
		// arrange 
		AclClass aclClass = new AclClass();
		aclClass.setClassName("blog.core.Post");
		QAclClass qAclClass = QAclClass.aclClass;
		when(mockRepository.findOne(qAclClass.className.eq(aclClass.getClassName()))).thenReturn(null);
		AclClass stubAclClass = new AclClass();
		stubAclClass.setId("someId");
		stubAclClass.setClassName("blog.core.Post");
		when(mockRepository.save(aclClass)).thenReturn(stubAclClass);
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		
		// action
		AclClass createAclClass = cacheAclClassService.createAclClass(aclClass);

		// verify
		assertNotNull(createAclClass);
		assertEquals("someId", stubAclClass.getId());
		assertEquals("blog.core.Post", createAclClass.getClassName());
		verify(mockRepository).findOne(any(Predicate.class));
		verify(mockRepository).save(aclClass);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void createAclClass_NullArgument_ThrowException() throws Exception {
		// arrange 
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		
		// action
		cacheAclClassService.createAclClass(null);

		// verify
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void createAclClass_NullClassName_ThrowException() throws Exception {
		// arrange 
		AclClass aclClass = new AclClass();
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		
		// action
		cacheAclClassService.createAclClass(aclClass);

		// verify
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void createAclClass_EmptyClassName_ThrowException() throws Exception {
		// arrange 
		AclClass aclClass = new AclClass();
		aclClass.setClassName("");
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		
		// action
		cacheAclClassService.createAclClass(aclClass);

		// verify
	}
	
	@Test(expected = ObjectClassAlreadyExistedException.class)
	public void createAclClass_ExistedClassName_ThrowException() throws Exception {
		// arrange 
		AclClass aclClass = new AclClass();
		aclClass.setClassName("blog.core.Existed");
		QAclClass qAclClass = QAclClass.aclClass;
		when(mockRepository.findOne(qAclClass.className.eq(aclClass.getClassName()))).thenReturn(aclClass);
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		
		// action
		cacheAclClassService.createAclClass(aclClass);

		// verify
	}
	
	@SuppressWarnings("unchecked")
	@Test
	public void getObjectClassName_ValidObjectClassId_ReturnDataFromDatastore() throws Exception {
		// arrange 
		String objectClassId = "1";
		AclClass stubClass = new AclClass();
		stubClass.setClassName("SampleClass");
		stubClass.setId(objectClassId);
		when(mockRepository.findOne(objectClassId)).thenReturn(stubClass);
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		
		// action
		String objectClassName = cacheAclClassService.getObjectClassName(objectClassId);

		// verify
		assertNotNull(objectClassName);
		assertEquals("SampleClass", objectClassName);
		Map<String, String> classNameToIdMap = (Map<String, String>)FieldUtils.getFieldValue(cacheAclClassService, "classNameToIdMap");
		assertTrue(classNameToIdMap.containsKey("SampleClass"));
		assertEquals(classNameToIdMap.get("SampleClass"), "1");
	}
	
	@Test(expected = ObjectClassNotExistException.class)
	public void getObjectClassName_NonExistedObjectClassId_ThrowException() throws Exception {
		// arrange 
		when(mockRepository.findOne(anyString())).thenReturn(null);
		SimpleCacheAclClassService cacheAclClassService = new SimpleCacheAclClassService(mockRepository);
		
		// action
		cacheAclClassService.getObjectClassName("nonExisted");
		
		// verify

	}
}
