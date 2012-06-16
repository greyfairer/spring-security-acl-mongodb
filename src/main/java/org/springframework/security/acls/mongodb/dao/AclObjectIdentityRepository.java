package org.springframework.security.acls.mongodb.dao;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.querydsl.QueryDslPredicateExecutor;
import org.springframework.security.acls.mongodb.model.AclObjectIdentity;


public interface AclObjectIdentityRepository extends MongoRepository<AclObjectIdentity, String>, QueryDslPredicateExecutor<AclObjectIdentity> {

}
