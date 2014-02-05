package org.springframework.security.acls.mongodb.model;

import static com.mysema.query.types.PathMetadataFactory.*;

import com.mysema.query.types.*;
import com.mysema.query.types.path.*;

import javax.annotation.Generated;


/**
 * QAclEntry is a Querydsl query type for AclEntry
 */
@Generated("com.mysema.query.codegen.EntitySerializer")
public class QAclEntry extends EntityPathBase<AclEntry> {

    private static final long serialVersionUID = 1529595655;

    public static final QAclEntry aclEntry = new QAclEntry("aclEntry");

    public final BooleanPath auditFailure = createBoolean("auditFailure");

    public final BooleanPath auditSuccess = createBoolean("auditSuccess");

    public final BooleanPath granting = createBoolean("granting");

    public final StringPath id = createString("id");

    public final NumberPath<Integer> mask = createNumber("mask", Integer.class);

    public final StringPath objectIdentityId = createString("objectIdentityId");

    public final NumberPath<Integer> order = createNumber("order", Integer.class);

    public final StringPath sid = createString("sid");

    public QAclEntry(String variable) {
        super(AclEntry.class, forVariable(variable));
    }

    public QAclEntry(Path<? extends AclEntry> entity) {
        super(entity.getType(), entity.getMetadata());
    }

    public QAclEntry(PathMetadata<?> metadata) {
        super(AclEntry.class, metadata);
    }

}

