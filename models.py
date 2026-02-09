from typing import Optional, List
from datetime import datetime
from sqlmodel import Field, SQLModel, Relationship

# === NEW: INVITE CODE MODEL ===
class InviteCode(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    code: str = Field(unique=True, index=True)
    created_by: str
    is_used: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.now)

# === UPDATED USER MODEL ===
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    role: str = Field(default="User") # "Admin" or "User"
    
    # Gamification
    petri_score: int = Field(default=10)
    petri_color: str = Field(default="#00ff00")
    last_active: datetime = Field(default_factory=datetime.now)

# ... (Keep all other models: Lab, Consumable, AuditLog, etc. unchanged)
# COPY PASTE THE REST OF YOUR MODELS HERE FROM PREVIOUS STEPS
class Lab(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    location: str
    resources: str = Field(default="General Bench")
    bookings: List["Booking"] = Relationship(back_populates="lab")
    user_limit: int = Field(default=5)

class Consumable(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    category: str = Field(default="General") 
    quantity: int = Field(default=0)
    unit: str = Field(default="units")       
    location: Optional[str] = None           
    min_level: int = Field(default=5)        
    order_flag: bool = Field(default=False)  
    buy_url: Optional[str] = None
    logs: List["AuditLog"] = Relationship(back_populates="consumable")

class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    action: str 
    user_name: str = Field(default="System")
    timestamp: datetime = Field(default_factory=datetime.now)
    details: Optional[str] = None
    sample_id: Optional[int] = Field(default=None, foreign_key="sample.id")
    sample: Optional["Sample"] = Relationship(back_populates="logs")
    consumable_id: Optional[int] = Field(default=None, foreign_key="consumable.id")
    consumable: Optional[Consumable] = Relationship(back_populates="logs")

class ExperimentTemplate(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None
    protocol: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)

class Attachment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    filename: str
    filepath: str
    uploaded_at: datetime = Field(default_factory=datetime.now)
    sample_id: Optional[int] = Field(default=None, foreign_key="sample.id")
    sample: Optional["Sample"] = Relationship(back_populates="attachments")
    experiment_id: Optional[int] = Field(default=None, foreign_key="experiment.id")
    experiment: Optional["Experiment"] = Relationship(back_populates="attachments")

class Experiment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str 
    description: Optional[str] = None 
    protocol: Optional[str] = None    
    date: datetime = Field(default_factory=datetime.now)
    status: str = Field(default="Planning") 
    pos_x: int = Field(default=50)
    pos_y: int = Field(default=50)
    project_id: int = Field(foreign_key="project.id")
    project: Optional["Project"] = Relationship(back_populates="experiments")
    samples: List["Sample"] = Relationship(back_populates="experiment")
    bookings: List["Booking"] = Relationship(back_populates="experiment")
    attachments: List["Attachment"] = Relationship(back_populates="experiment")
    progress_json: str = Field(default="{}")

class ExperimentLink(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id")
    source_id: int = Field(foreign_key="experiment.id")
    target_id: int = Field(foreign_key="experiment.id")

class Freezer(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    location: Optional[str] = None
    boxes: List["Box"] = Relationship(back_populates="freezer")

class Box(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    rows: int = 9
    cols: int = 9
    shelf: str = Field(default="General")
    color: str = Field(default="#333333")
    icon: str = Field(default="fa-box")
    label_text: Optional[str] = None
    freezer_id: Optional[int] = Field(default=None, foreign_key="freezer.id")
    freezer: Optional[Freezer] = Relationship(back_populates="boxes")
    samples: List["Sample"] = Relationship(back_populates="box")

class SampleLineageLink(SQLModel, table=True):
    parent_id: Optional[int] = Field(default=None, foreign_key="sample.id", primary_key=True)
    child_id: Optional[int] = Field(default=None, foreign_key="sample.id", primary_key=True)

# 2. Define the Sample Table SECOND
class Sample(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    sample_type: str = Field(default="Other")
    lot_number: Optional[str] = None
    notes: Optional[str] = None
    amount_left: Optional[str] = None
    expiry_date: Optional[str] = None 
    is_low_stock: bool = Field(default=False)
    host_species: Optional[str] = None
    passage_number: Optional[int] = None
    resistance: Optional[str] = None
    
    # Location
    box_id: Optional[int] = Field(default=None, foreign_key="box.id")
    box: Optional["Box"] = Relationship(back_populates="samples")
    row_idx: int
    col_idx: int

    # Experiment Link
    experiment_id: Optional[int] = Field(default=None, foreign_key="experiment.id")
    experiment: Optional["Experiment"] = Relationship(back_populates="samples")

    # --- NEW: Many-to-Many Lineage ---
    # We explicitly tell SQLModel how to join the tables using string queries
    parents: List["Sample"] = Relationship(
        back_populates="children",
        link_model=SampleLineageLink,
        sa_relationship_kwargs={
            "primaryjoin": "Sample.id==SampleLineageLink.child_id",
            "secondaryjoin": "Sample.id==SampleLineageLink.parent_id"
        }
    )
    
    children: List["Sample"] = Relationship(
        back_populates="parents",
        link_model=SampleLineageLink,
        sa_relationship_kwargs={
            "primaryjoin": "Sample.id==SampleLineageLink.parent_id",
            "secondaryjoin": "Sample.id==SampleLineageLink.child_id"
        }
    )
    # ---------------------------------

    # Logs & Attachments
    logs: List["AuditLog"] = Relationship(back_populates="sample")
    attachments: List["Attachment"] = Relationship(back_populates="sample")

class Booking(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    resource: str
    start_time: datetime
    end_time: datetime
    user_name: str
    description: Optional[str] = None
    lab_id: Optional[int] = Field(default=None, foreign_key="lab.id")
    lab: Optional[Lab] = Relationship(back_populates="bookings")
    project_id: Optional[int] = Field(default=None, foreign_key="project.id")
    project: Optional["Project"] = Relationship(back_populates="bookings")
    experiment_id: Optional[int] = Field(default=None, foreign_key="experiment.id")
    experiment: Optional[Experiment] = Relationship(back_populates="bookings")

class Project(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    owner: str 
    experiments: List[Experiment] = Relationship(back_populates="project")
    bookings: List[Booking] = Relationship(back_populates="project")

class OrderRequest(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    item_name: str
    catalog_number: Optional[str] = None
    url: Optional[str] = None
    quantity: int = 1
    reason: Optional[str] = None
    
    requester: str # Username
    status: str = Field(default="Pending") # Pending, Approved, Ordered, Received
    
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)