from mongoengine import Document, StringField, BooleanField, EmbeddedDocument, EmbeddedDocumentField, ListField, FloatField
from mongoengine import connect

# Connect to MongoDB
connect('NVD_Data', host='mongodb+srv://gireesh_04:ROWifs5BzMANczn4@cluster0.rfcdd.mongodb.net/NVD_Data')

# Embedded schema for CVSS metrics
class CvssData(EmbeddedDocument):
    version = StringField(required=True)
    vectorString = StringField(required=True)
    accessVector = StringField(required=True)
    accessComplexity = StringField(required=True)
    authentication = StringField(required=True)
    confidentialityImpact = StringField(required=True)
    integrityImpact = StringField(required=True)
    availabilityImpact = StringField(required=True)
    baseScore = FloatField(required=True, default=0.0)

class CvssMetricV2(EmbeddedDocument):
    source = StringField(required=True)
    type = StringField(required=True)
    cvssData = EmbeddedDocumentField(CvssData, required=True)
    baseSeverity = StringField(required=True)
    exploitabilityScore = FloatField(required=True)
    impactScore = FloatField(required=True)
    acInsufInfo = BooleanField(required=True, default=False)
    obtainAllPrivilege = BooleanField(required=True, default=False)
    obtainUserPrivilege = BooleanField(required=True, default=False)
    obtainOtherPrivilege = BooleanField(required=True, default=False)
    userInteractionRequired = BooleanField(required=True, default=False)

# Embedded schema for descriptions
class Description(EmbeddedDocument):
    lang = StringField()
    value = StringField()

# Embedded schema for configuration nodes

# Define the Node class as an EmbeddedDocument
class CpeMatch(EmbeddedDocument):
    vulnerable = BooleanField(default=False)
    criteria = StringField()
    matchCriteriaId = StringField()

# Define the Node class as an EmbeddedDocument
class Node(EmbeddedDocument):
    operator = StringField()
    negate = BooleanField(default=False)
    cpeMatch = ListField(EmbeddedDocumentField(CpeMatch))  # List of CpeMatch embedded documents

# Define Configuration class as an EmbeddedDocument
class Configuration(EmbeddedDocument):
    nodes = ListField(EmbeddedDocumentField(Node))  # List of Embedded Node documents

# Define CVE class as a Document, which includes configurations as an EmbeddedDocument
class CVE(Document):
    cve_id = StringField()
    sourceIdentifier = StringField()
    published = StringField()
    lastModified = StringField()
    vulnStatus = StringField()
    descriptions = ListField()  # Assuming Description is an embedded document
    metrics = ListField()  # Assuming CVSS data is stored here
    configurations = ListField(EmbeddedDocumentField(Configuration))