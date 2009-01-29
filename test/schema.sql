CREATE TABLE 'test_models' (
  'id' INTEGER PRIMARY KEY NOT NULL,
  'test_attr_through_id' INTEGER,
  'content' text, 
  'created_at' datetime, 
  'updated_at' datetime
);

CREATE TABLE 'test_attrs' (
  'id' INTEGER PRIMARY KEY NOT NULL, 
  'test_model_id' integer,
  'test_another_model_id' integer,
  'test_attr_through_id' INTEGER,
  'n_way_join_item_id' INTEGER,
  'test_model_security_model_id' integer,
  'attr' integer default 1
);

CREATE TABLE 'test_attr_throughs' (
  'id' INTEGER PRIMARY KEY NOT NULL, 
  'test_attr_id' integer
);

CREATE TABLE 'test_model_security_models' (
  'id' INTEGER PRIMARY KEY NOT NULL, 
  'attr' integer default 1, 
  'attr_2' integer default 1
);

CREATE TABLE 'n_way_join_items' (
  'id' INTEGER PRIMARY KEY NOT NULL
);
