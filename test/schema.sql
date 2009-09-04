CREATE TABLE 'test_models' (
  'id' INTEGER PRIMARY KEY NOT NULL,
  'test_attr_through_id' INTEGER,
  'content' text,
  'country_id' integer,
  'created_at' datetime, 
  'updated_at' datetime
);

CREATE TABLE 'test_attrs' (
  'id' INTEGER PRIMARY KEY NOT NULL, 
  'test_model_id' integer,
  'test_another_model_id' integer,
  'test_a_third_model_id' integer,
  'branch_id' integer,
  'company_id' integer,
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

CREATE TABLE 'branches' (
  'id' INTEGER PRIMARY KEY NOT NULL,
  'company_id' integer,
  'name' text
);

CREATE TABLE 'companies' (
  'id' INTEGER PRIMARY KEY NOT NULL,
  'country_id' integer,
  'type' text,
  'name' text
);

CREATE TABLE 'countries' (
  'id' INTEGER PRIMARY KEY NOT NULL,
  'name' text
);
