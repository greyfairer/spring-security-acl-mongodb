package org.springframework.security.acls.mongodb.model;

import static com.mysema.query.types.PathMetadataFactory.*;

import com.mysema.query.types.*;
import com.mysema.query.types.path.*;

import javax.annotation.Generated;


/**
 * QAclClass is a Querydsl query type for AclClass
 */
@Generated("com.mysema.query.codegen.EntitySerializer")
public class QAclClass extends EntityPathBase<AclClass> {

    private static final long serialVersionUID = 1527670797;

    public static final QAclClass aclClass = new QAclClass("aclClass");

    public final StringPath className = createString("className");

    public final StringPath id = createString("id");

    public QAclClass(String variable) {
        super(AclClass.class, forVariable(variable));
    }

    public QAclClass(Path<? extends AclClass> entity) {
        super(entity.getType(), entity.getMetadata());
    }

    public QAclClass(PathMetadata<?> metadata) {
        super(AclClass.class, metadata);
    }

}

