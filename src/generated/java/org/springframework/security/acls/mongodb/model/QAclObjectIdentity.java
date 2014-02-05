package org.springframework.security.acls.mongodb.model;

import static com.mysema.query.types.PathMetadataFactory.*;

import com.mysema.query.types.*;
import com.mysema.query.types.path.*;

import javax.annotation.Generated;


/**
 * QAclObjectIdentity is a Querydsl query type for AclObjectIdentity
 */
@Generated("com.mysema.query.codegen.EntitySerializer")
public class QAclObjectIdentity extends EntityPathBase<AclObjectIdentity> {

    private static final long serialVersionUID = -1097620952;

    public static final QAclObjectIdentity aclObjectIdentity = new QAclObjectIdentity("aclObjectIdentity");

    public final BooleanPath entriesInheriting = createBoolean("entriesInheriting");

    public final StringPath id = createString("id");

    public final StringPath objectIdClass = createString("objectIdClass");

    public final StringPath objectIdIdentity = createString("objectIdIdentity");

    public final StringPath ownerId = createString("ownerId");

    public final StringPath parentObjectId = createString("parentObjectId");

    public QAclObjectIdentity(String variable) {
        super(AclObjectIdentity.class, forVariable(variable));
    }

    public QAclObjectIdentity(Path<? extends AclObjectIdentity> entity) {
        super(entity.getType(), entity.getMetadata());
    }

    public QAclObjectIdentity(PathMetadata<?> metadata) {
        super(AclObjectIdentity.class, metadata);
    }

}

