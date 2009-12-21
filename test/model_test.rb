require File.join(File.dirname(__FILE__), 'test_helper.rb')
require File.join(File.dirname(__FILE__), %w{.. lib declarative_authorization in_model})

ActiveRecord::Base.send :include, Authorization::AuthorizationInModel
#ActiveRecord::Base.logger = Logger.new(STDOUT)

options = {:adapter => 'sqlite3', :timeout => 500, :database => ':memory:'}
ActiveRecord::Base.establish_connection(options)
ActiveRecord::Base.configurations = { 'sqlite3_ar_integration' => options }
ActiveRecord::Base.connection

File.read(File.dirname(__FILE__) + "/schema.sql").split(';').each do |sql|
  ActiveRecord::Base.connection.execute(sql) unless sql.blank?
end

class TestModel < ActiveRecord::Base
  has_many :test_attrs
  has_many :test_another_attrs, :class_name => "TestAttr", :foreign_key => :test_another_model_id
  has_many :test_attr_throughs, :through => :test_attrs
  has_many :test_attrs_with_attr, :class_name => "TestAttr", :conditions => {:attr => 1}
  has_many :test_attr_throughs_with_attr, :through => :test_attrs, 
    :class_name => "TestAttrThrough", :source => :test_attr_throughs,
    :conditions => "test_attrs.attr = 1"
  has_one :test_attr_has_one, :class_name => "TestAttr"
  has_one :test_attr_throughs_with_attr_and_has_one, :through => :test_attrs,
    :class_name => "TestAttrThrough", :source => :test_attr_throughs,
    :conditions => "test_attrs.attr = 1"

  has_and_belongs_to_many :test_attr_throughs_habtm, :join_table => :test_attrs,
      :class_name => "TestAttrThrough"

  named_scope :with_content, :conditions => "test_models.content IS NOT NULL"

  # Primary key test
  # take this out for Rails prior to 2.2
  if ([Rails::VERSION::MAJOR, Rails::VERSION::MINOR] <=> [2, 2]) > -1
    has_many :test_attrs_with_primary_id, :class_name => "TestAttr",
      :primary_key => :test_attr_through_id, :foreign_key => :test_attr_through_id
    has_many :test_attr_throughs_with_primary_id, 
      :through => :test_attrs_with_primary_id, :class_name => "TestAttrThrough",
      :source => :n_way_join_item
  end

  # for checking for unnecessary queries
  mattr_accessor :query_count
  def self.find(*args)
    self.query_count ||= 0
    self.query_count += 1
    super(*args)
  end
end

class NWayJoinItem < ActiveRecord::Base
  has_many :test_attrs
  has_many :others, :through => :test_attrs, :source => :n_way_join_item
end

class TestAttr < ActiveRecord::Base
  belongs_to :test_model
  belongs_to :test_another_model, :class_name => "TestModel", :foreign_key => :test_another_model_id
  belongs_to :test_a_third_model, :class_name => "TestModel", :foreign_key => :test_a_third_model_id
  belongs_to :n_way_join_item
  belongs_to :test_attr
  belongs_to :branch
  belongs_to :company
  has_many :test_attr_throughs
  attr_reader :role_symbols
  def initialize (*args)
    @role_symbols = []
    super(*args)
  end
end

class TestAttrThrough < ActiveRecord::Base
  belongs_to :test_attr
end

class TestModelSecurityModel < ActiveRecord::Base
  has_many :test_attrs
  using_access_control
end
class TestModelSecurityModelWithFind < ActiveRecord::Base
  set_table_name "test_model_security_models"
  has_many :test_attrs
  using_access_control :include_read => true, 
    :context => :test_model_security_models
end

class Branch < ActiveRecord::Base
  has_many :test_attrs
  belongs_to :company
end
class Company < ActiveRecord::Base
  has_many :test_attrs
  has_many :branches
  belongs_to :country
end
class SmallCompany < Company
  def self.decl_auth_context
    :companies
  end
end
class Country < ActiveRecord::Base
  has_many :test_models
  has_many :companies
end

class NamedScopeModelTest < Test::Unit::TestCase
  def test_multiple_deep_ored_belongs_to
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_model => {:test_attrs => contains {user}}
            if_attribute :test_another_model => {:test_attrs => contains {user}}
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!
    test_attr_1 = TestAttr.create! :test_model_id => test_model_1.id,
                      :test_another_model_id => test_model_2.id

    user = MockUser.new(:test_role, :id => test_attr_1)
    assert_equal 1, TestAttr.with_permissions_to(:read, :user => user).length
    TestAttr.delete_all
    TestModel.delete_all
  end

  def test_with_belongs_to_and_has_many_with_contains
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_model => { :test_attrs => contains { user.test_attr_value } }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_attr_1 = TestAttr.create!
    test_model_1 = TestModel.create!
    test_model_1.test_attrs.create!

    user = MockUser.new(:test_role, :test_attr_value => test_model_1.test_attrs.first.id )
    assert_equal 1, TestAttr.with_permissions_to( :read, :context => :test_attrs, :user => user ).length
    assert_equal 1, TestAttr.with_permissions_to( :read, :user => user ).length
    assert_raise Authorization::NotAuthorized do
      TestAttr.with_permissions_to( :update_test_attrs, :user => user )
    end
    TestAttr.delete_all
    TestModel.delete_all
  end

  def test_with_nested_has_many
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :companies, :to => :read do
            if_attribute :branches => { :test_attrs => { :attr => is { user.test_attr_value } } }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    allowed_company = Company.create!
    allowed_company.branches.create!.test_attrs.create!(:attr => 1)
    allowed_company.branches.create!.test_attrs.create!(:attr => 2)

    prohibited_company = Company.create!
    prohibited_company.branches.create!.test_attrs.create!(:attr => 3)

    user = MockUser.new(:test_role, :test_attr_value => 1)
    prohibited_user = MockUser.new(:test_role, :test_attr_value => 4)
    assert_equal 1, Company.with_permissions_to(:read, :user => user).length
    assert_equal 0, Company.with_permissions_to(:read, :user => prohibited_user).length

    Company.delete_all
    Branch.delete_all
    TestAttr.delete_all
  end

  def test_with_nested_has_many_through
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attr_throughs => { :test_attr => { :attr => is { user.test_attr_value } } }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    allowed_model = TestModel.create!
    allowed_model.test_attrs.create!(:attr => 1).test_attr_throughs.create!
    allowed_model.test_attrs.create!(:attr => 2).test_attr_throughs.create!

    prohibited_model = TestModel.create!
    prohibited_model.test_attrs.create!(:attr => 3).test_attr_throughs.create!

    user = MockUser.new(:test_role, :test_attr_value => 1)
    prohibited_user = MockUser.new(:test_role, :test_attr_value => 4)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    assert_equal 0, TestModel.with_permissions_to(:read, :user => prohibited_user).length

    TestModel.delete_all
    TestAttrThrough.delete_all
    TestAttr.delete_all
  end

  def test_with_is
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :id => is { user.test_attr_value }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    TestModel.create!

    user = MockUser.new(:test_role, :test_attr_value => test_model_1.id)
    assert_equal 1, TestModel.with_permissions_to(:read,
      :context => :test_models, :user => user).length
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    assert_raise Authorization::NotAuthorized do
      TestModel.with_permissions_to(:update_test_models, :user => user)
    end
    TestModel.delete_all
  end

  def test_named_scope_on_proxy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :id => is { user.test_attr_value }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_attr_1 = test_model_1.test_attrs.create!
    test_model_1.test_attrs.create!
    TestAttr.create!

    user = MockUser.new(:test_role, :test_attr_value => test_attr_1.id)
    assert_equal 1, test_model_1.test_attrs.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_named_scope_on_named_scope
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :country_id => 1
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    TestModel.create!(:country_id => 1, :content => "Content")
    TestModel.create!(:country_id => 1)
    TestModel.create!(:country_id => 2, :content => "Content")

    user = MockUser.new(:test_role)

    TestModel.query_count = 0
    assert_equal 2, TestModel.with_permissions_to(:read, :user => user).length
    assert_equal 1, TestModel.query_count

    TestModel.query_count = 0
    assert_equal 1, TestModel.with_content.with_permissions_to(:read, :user => user).length
    assert_equal 1, TestModel.query_count

    TestModel.query_count = 0
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).with_content.length
    assert_equal 1, TestModel.query_count

    TestModel.delete_all
  end

  def test_with_modified_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :companies, :to => :read do
            if_attribute :id => is { user.test_company_id }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_company = SmallCompany.create!

    user = MockUser.new(:test_role, :test_company_id => test_company.id)
    assert_equal 1, SmallCompany.with_permissions_to(:read,
      :user => user).length
    SmallCompany.delete_all
  end

  def test_with_is_nil
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :content => nil
          end
        end
        role :test_role_not_nil do
          has_permission_on :test_models, :to => :read do
            if_attribute :content => is_not { nil }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create! :content => "Content"

    assert_equal test_model_1, TestModel.with_permissions_to(:read,
      :context => :test_models, :user => MockUser.new(:test_role)).first
    assert_equal test_model_2, TestModel.with_permissions_to(:read,
      :context => :test_models, :user => MockUser.new(:test_role_not_nil)).first
    TestModel.delete_all
  end

  def test_with_not_is
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :id => is_not { user.test_attr_value }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    TestModel.create!

    user = MockUser.new(:test_role, :test_attr_value => test_model_1.id)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
  end

  def test_with_empty_obligations
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read
        end
      end
    }
    Authorization::Engine.instance(reader)

    TestModel.create!

    user = MockUser.new(:test_role)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    assert_raise Authorization::NotAuthorized do
      TestModel.with_permissions_to(:update, :user => user)
    end
    TestModel.delete_all
  end

  def test_multiple_obligations
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :id => is { user.test_attr_value }
          end
          has_permission_on :test_models, :to => :read do
            if_attribute :id => is { user.test_attr_value_2 }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!

    user = MockUser.new(:test_role, :test_attr_value => test_model_1.id,
                        :test_attr_value_2 => test_model_2.id)
    assert_equal 2, TestModel.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
  end

  def test_multiple_roles
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :attr => [1,2]
          end
        end

        role :test_role_2 do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :attr => [2,3]
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    TestAttr.create! :attr => 1
    TestAttr.create! :attr => 2
    TestAttr.create! :attr => 3

    user = MockUser.new(:test_role)
    assert_equal 2, TestAttr.with_permissions_to(:read, :user => user).length
    TestAttr.delete_all
  end

  def test_multiple_and_empty_obligations
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :id => is { user.test_attr_value }
          end
          has_permission_on :test_models, :to => :read
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    TestModel.create!

    user = MockUser.new(:test_role, :test_attr_value => test_model_1.id)
    assert_equal 2, TestModel.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
  end

  def test_multiple_attributes
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :id => is { user.test_attr_value }, :content => "bla"
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create! :content => 'bla'
    TestModel.create! :content => 'bla'
    TestModel.create!

    user = MockUser.new(:test_role, :test_attr_value => test_model_1.id)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
  end

  def test_multiple_belongs_to
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_model => is {user}
            if_attribute :test_another_model => is {user}
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_attr_1 = TestAttr.create! :test_model_id => 1, :test_another_model_id => 2

    user = MockUser.new(:test_role, :id => 1)
    assert_equal 1, TestAttr.with_permissions_to(:read, :user => user).length
    TestAttr.delete_all
  end

  def test_with_is_and_priv_hierarchy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      privileges do
        privilege :read do
          includes :list, :show
        end
      end
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :id => is { user.test_attr_value }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    TestModel.create!

    user = MockUser.new(:test_role, :test_attr_value => test_model_1.id)
    assert_equal 1, TestModel.with_permissions_to(:list,
      :context => :test_models, :user => user).length
    assert_equal 1, TestModel.with_permissions_to(:list, :user => user).length

    TestModel.delete_all
  end

  def test_with_is_and_belongs_to
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_model => is { user.test_model }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_1.test_attrs.create!
    TestModel.create!.test_attrs.create!

    user = MockUser.new(:test_role, :test_model => test_model_1)
    assert_equal 1, TestAttr.with_permissions_to(:read,
      :context => :test_attrs, :user => user).length

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_deep_attribute
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_model => {:id => is { user.test_model_id } }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_1.test_attrs.create!
    TestModel.create!.test_attrs.create!

    user = MockUser.new(:test_role, :test_model_id => test_model_1.id)
    assert_equal 1, TestAttr.with_permissions_to(:read,
      :context => :test_attrs, :user => user).length

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_anded_rules
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read, :join_by => :and do
            if_attribute :test_model => is { user.test_model }
            if_attribute :attr => 1
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_1.test_attrs.create!(:attr => 1)
    TestModel.create!.test_attrs.create!(:attr => 1)
    TestModel.create!.test_attrs.create!

    user = MockUser.new(:test_role, :test_model => test_model_1)
    assert_equal 1, TestAttr.with_permissions_to(:read,
      :context => :test_attrs, :user => user).length

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_contains
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attrs => contains { user }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!
    test_model_1.test_attrs.create!
    test_model_1.test_attrs.create!
    test_model_2.test_attrs.create!

    user = MockUser.new(:test_role,
                        :id => test_model_1.test_attrs.first.id)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).find(:all, :conditions => {:id => test_model_1.id}).length

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_does_not_contain
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attrs => does_not_contain { user }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!
    test_model_1.test_attrs.create!
    test_model_2.test_attrs.create!

    user = MockUser.new(:test_role,
                        :id => test_model_1.test_attrs.first.id)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_contains_conditions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attrs_with_attr => contains { user }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!
    test_model_1.test_attrs_with_attr.create!
    test_model_1.test_attrs.create!(:attr => 2)
    test_model_2.test_attrs_with_attr.create!
    test_model_2.test_attrs.create!(:attr => 2)

    #assert_equal 1, test_model_1.test_attrs_with_attr.length
    user = MockUser.new(:test_role,
                        :id => test_model_1.test_attrs.first.id)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    user = MockUser.new(:test_role,
                        :id => test_model_1.test_attrs.last.id)
    assert_equal 0, TestModel.with_permissions_to(:read, :user => user).length

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_contains_through_conditions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attr_throughs_with_attr => contains { user }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!
    test_model_1.test_attrs.create!(:attr => 1).test_attr_throughs.create!
    test_model_1.test_attrs.create!(:attr => 2).test_attr_throughs.create!
    test_model_2.test_attrs.create!(:attr => 1).test_attr_throughs.create!
    test_model_2.test_attrs.create!(:attr => 2).test_attr_throughs.create!

    #assert_equal 1, test_model_1.test_attrs_with_attr.length
    user = MockUser.new(:test_role,
                        :id => test_model_1.test_attr_throughs.first.id)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    user = MockUser.new(:test_role,
                        :id => test_model_1.test_attr_throughs.last.id)
    assert_equal 0, TestModel.with_permissions_to(:read, :user => user).length

    TestModel.delete_all
    TestAttrThrough.delete_all
    TestAttr.delete_all
  end

  def test_with_contains_habtm
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attr_throughs_habtm => contains { user.test_attr_through_id }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!
    test_attr_through_1 = TestAttrThrough.create!
    test_attr_through_2 = TestAttrThrough.create!
    TestAttr.create! :test_model_id => test_model_1.id, :test_attr_through_id => test_attr_through_1.id
    TestAttr.create! :test_model_id => test_model_2.id, :test_attr_through_id => test_attr_through_2.id

    user = MockUser.new(:test_role,
                        :test_attr_through_id => test_model_1.test_attr_throughs_habtm.first.id)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    assert_equal test_model_1, TestModel.with_permissions_to(:read, :user => user)[0]

    TestModel.delete_all
    TestAttrThrough.delete_all
    TestAttr.delete_all
  end

  # take this out for Rails prior to 2.2
  if ([Rails::VERSION::MAJOR, Rails::VERSION::MINOR] <=> [2, 2]) > -1
    def test_with_contains_through_primary_key
      reader = Authorization::Reader::DSLReader.new
      reader.parse %{
        authorization do
          role :test_role do
            has_permission_on :test_models, :to => :read do
              if_attribute :test_attr_throughs_with_primary_id => contains { user }
            end
          end
        end
      }
      Authorization::Engine.instance(reader)

      test_attr_through_1 = TestAttrThrough.create!
      test_item = NWayJoinItem.create!
      test_model_1 = TestModel.create!(:test_attr_through_id => test_attr_through_1.id)
      test_attr_1 = TestAttr.create!(:test_attr_through_id => test_attr_through_1.id,
          :n_way_join_item_id => test_item.id)

      user = MockUser.new(:test_role,
                          :id => test_attr_through_1.id)
      assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length

      TestModel.delete_all
      TestAttrThrough.delete_all
      TestAttr.delete_all
    end
  end

  def test_with_intersects_with
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attrs => intersects_with { user.test_attrs }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!
    test_model_1.test_attrs.create!
    test_model_1.test_attrs.create!
    test_model_1.test_attrs.create!
    test_model_2.test_attrs.create!

    user = MockUser.new(:test_role,
                        :test_attrs => [test_model_1.test_attrs.first, TestAttr.create!])
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length

    user = MockUser.new(:test_role,
                        :test_attrs => [TestAttr.create!])
    assert_equal 0, TestModel.with_permissions_to(:read, :user => user).length

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_is_and_has_one
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do :test_attr_has_one
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attr_has_one => is { user.test_attr }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_attr_1 = test_model_1.test_attrs.create!
    TestModel.create!.test_attrs.create!

    user = MockUser.new(:test_role, :test_attr => test_attr_1)
    assert_equal 1, TestModel.with_permissions_to(:read,
      :context => :test_models, :user => user).length

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_is_and_has_one_through_conditions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attr_throughs_with_attr_and_has_one => contains { user }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!
    test_model_1.test_attrs.create!(:attr => 1).test_attr_throughs.create!
    test_model_1.test_attrs.create!(:attr => 2).test_attr_throughs.create!
    test_model_2.test_attrs.create!(:attr => 1).test_attr_throughs.create!
    test_model_2.test_attrs.create!(:attr => 2).test_attr_throughs.create!

    #assert_equal 1, test_model_1.test_attrs_with_attr.length
    user = MockUser.new(:test_role,
                        :id => test_model_1.test_attr_throughs.first.id)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    user = MockUser.new(:test_role,
                        :id => test_model_1.test_attr_throughs.last.id)
    assert_equal 0, TestModel.with_permissions_to(:read, :user => user).length

    TestModel.delete_all
    TestAttr.delete_all
    TestAttrThrough.delete_all
  end

  def test_with_is_in
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_model => is_in { [user.test_model, user.test_model_2] }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!
    test_model_1.test_attrs.create!
    TestModel.create!.test_attrs.create!

    user = MockUser.new(:test_role, :test_model => test_model_1,
      :test_model_2 => test_model_2)
    assert_equal 1, TestAttr.with_permissions_to(:read,
      :context => :test_attrs, :user => user).length

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_not_is_in
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_model => is_not_in { [user.test_model, user.test_model_2] }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_model_2 = TestModel.create!
    test_model_1.test_attrs.create!
    TestModel.create!.test_attrs.create!

    user = MockUser.new(:test_role, :test_model => test_model_1,
      :test_model_2 => test_model_2)
    assert_equal 1, TestAttr.with_permissions_to(:read,
      :context => :test_attrs, :user => user).length

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_if_permitted_to
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attrs => contains { user }
          end
          has_permission_on :test_attrs, :to => :read do
            if_permitted_to :read, :test_model
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_attr_1 = test_model_1.test_attrs.create!

    user = MockUser.new(:test_role, :id => test_attr_1.id)
    assert_equal 1, TestAttr.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_if_permitted_to_with_no_child_permissions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :another_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attrs => contains { user }
          end
        end
        role :additional_if_attribute do
          has_permission_on :test_attrs, :to => :read do
            if_permitted_to :read, :test_model
            if_attribute :test_model => {:test_attrs => contains { user }}
          end
        end
        role :only_permitted_to do
          has_permission_on :test_attrs, :to => :read do
            if_permitted_to :read, :test_model
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_attr_1 = test_model_1.test_attrs.create!

    user = MockUser.new(:only_permitted_to, :another_role, :id => test_attr_1.id)
    also_allowed_user = MockUser.new(:additional_if_attribute, :id => test_attr_1.id)
    non_allowed_user = MockUser.new(:only_permitted_to, :id => test_attr_1.id)

    assert_equal 1, TestAttr.with_permissions_to(:read, :user => user).length
    assert_equal 1, TestAttr.with_permissions_to(:read, :user => also_allowed_user).length
    assert_raise Authorization::NotAuthorized do
      TestAttr.with_permissions_to(:read, :user => non_allowed_user).find(:all)
    end

    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_if_permitted_to_with_context_from_model
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_another_attrs => contains { user }
          end
          has_permission_on :test_attrs, :to => :read do
            if_permitted_to :read, :test_another_model
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_attr_1 = test_model_1.test_another_attrs.create!

    user = MockUser.new(:test_role, :id => test_attr_1.id)
    non_allowed_user = MockUser.new(:test_role, :id => 111)

    assert_equal 1, TestAttr.with_permissions_to(:read, :user => user).length
    assert_equal 0, TestAttr.with_permissions_to(:read, :user => non_allowed_user).length
    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_has_many_if_permitted_to
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_permitted_to :read, :test_attrs
          end
          has_permission_on :test_attrs, :to => :read do
            if_attribute :attr => is { user.id }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_attr_1 = test_model_1.test_attrs.create!(:attr => 111)

    user = MockUser.new(:test_role, :id => test_attr_1.attr)
    non_allowed_user = MockUser.new(:test_role, :id => 333)
    assert_equal 1, TestModel.with_permissions_to(:read, :user => user).length
    assert_equal 0, TestModel.with_permissions_to(:read, :user => non_allowed_user).length
    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_deep_has_many_if_permitted_to
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :branches, :to => :read do
            if_attribute :name => "A Branch"
          end
          has_permission_on :companies, :to => :read do
            if_permitted_to :read, :test_attrs => :branch
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    readable_company = Company.create!
    readable_company.test_attrs.create!(:branch => Branch.create!(:name => "A Branch"))

    forbidden_company = Company.create!
    forbidden_company.test_attrs.create!(:branch => Branch.create!(:name => "Different Branch"))

    user = MockUser.new(:test_role)
    assert_equal 1, Company.with_permissions_to(:read, :user => user).length
    Company.delete_all
    Branch.delete_all
    TestAttr.delete_all
  end

  def test_with_if_permitted_to_and_empty_obligations
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read
          has_permission_on :test_attrs, :to => :read do
            if_permitted_to :read, :test_model
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_attr_1 = test_model_1.test_attrs.create!

    user = MockUser.new(:test_role)
    assert_equal 1, TestAttr.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_if_permitted_to_nil
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attrs => contains { user }
          end
          has_permission_on :test_attrs, :to => :read do
            if_permitted_to :read, :test_model
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_attr_1 = TestAttr.create!

    user = MockUser.new(:test_role, :id => test_attr_1.id)
    assert_equal 0, TestAttr.with_permissions_to(:read, :user => user).length
    TestAttr.delete_all
  end

  def test_with_if_permitted_to_self
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attrs => contains { user }
          end
          has_permission_on :test_models, :to => :update do
            if_permitted_to :read
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create!
    test_attr_1 = test_model_1.test_attrs.create!
    test_attr_2 = TestAttr.create!

    user = MockUser.new(:test_role, :id => test_attr_1.id)
    assert_equal 1, TestModel.with_permissions_to(:update, :user => user).length
    TestAttr.delete_all
    TestModel.delete_all
  end

  def test_with_has_many_and_reoccuring_tables
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_another_model => { :content => 'test_1_2' },
                :test_model => { :content => 'test_1_1' }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_attr_1 = TestAttr.create!(
        :test_model => TestModel.create!(:content => 'test_1_1'),
        :test_another_model => TestModel.create!(:content => 'test_1_2')
      )
    test_attr_2 = TestAttr.create!(
        :test_model => TestModel.create!(:content => 'test_2_1'),
        :test_another_model => TestModel.create!(:content => 'test_2_2')
      )

    user = MockUser.new(:test_role)
    assert_equal 1, TestAttr.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_ored_rules_and_reoccuring_tables
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_another_model => { :content => 'test_1_2' },
                :test_model => { :content => 'test_1_1' }
          end
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_another_model => { :content => 'test_2_2' },
                :test_model => { :test_attrs => contains {user.test_attr} }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_attr_1 = TestAttr.create!(
        :test_model => TestModel.create!(:content => 'test_1_1'),
        :test_another_model => TestModel.create!(:content => 'test_1_2')
      )
    test_attr_2 = TestAttr.create!(
        :test_model => TestModel.create!(:content => 'test_2_1'),
        :test_another_model => TestModel.create!(:content => 'test_2_2')
      )
    test_attr_2.test_model.test_attrs.create!

    user = MockUser.new(:test_role, :test_attr => test_attr_2.test_model.test_attrs.last)
    assert_equal 2, TestAttr.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_with_many_ored_rules_and_reoccuring_tables
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :branch => { :company => { :country => {
                :test_models => contains { user.test_model }
              }} }
            if_attribute :company => { :country => {
                :test_models => contains { user.test_model }
              }}
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    country = Country.create!(:name => 'country_1')
    country.test_models.create!
    test_attr_1 = TestAttr.create!(
        :branch => Branch.create!(:name => 'branch_1',
            :company => Company.create!(:name => 'company_1',
                :country => country))
      )
    test_attr_2 = TestAttr.create!(
        :company => Company.create!(:name => 'company_2',
            :country => country)
      )

    user = MockUser.new(:test_role, :test_model => country.test_models.first)

    assert_equal 2, TestAttr.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
    TestAttr.delete_all
  end
end

class ModelTest < Test::Unit::TestCase
  def test_permit_with_has_one_raises_no_name_error
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do :test_attr_has_one
        role :test_role do
          has_permission_on :test_attrs, :to => :update do
            if_attribute :id => is { user.test_attr.id }
          end
        end
      end
    }
    instance = Authorization::Engine.instance(reader)
    
    test_model = TestModel.create!
    test_attr = test_model.create_test_attr_has_one
    assert !test_attr.new_record?
    
    user = MockUser.new(:test_role, :test_attr => test_attr)
    
    assert_nothing_raised do
      assert instance.permit?(:update, :user => user, :object => test_model.test_attr_has_one) 
    end
    
    TestModel.delete_all
    TestAttr.delete_all
  end

  def test_model_security_write_allowed
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_model_security_models do
            to :read, :create, :update, :delete
            if_attribute :attr => is { 1 }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    Authorization.current_user = MockUser.new(:test_role)
    assert(object = TestModelSecurityModel.create)

    assert_nothing_raised { object.update_attributes(:attr_2 => 2) }
    object.reload
    assert_equal 2, object.attr_2
    object.destroy
    assert_raise ActiveRecord::RecordNotFound do
      TestModelSecurityModel.find(object.id)
    end
  end

  def test_model_security_write_not_allowed_no_privilege
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_model_security_models do
            to :read, :create, :update, :delete
            if_attribute :attr => is { 1 }
          end
        end
        role :test_role_restricted do
        end
      end
    }
    Authorization::Engine.instance(reader)

    Authorization.current_user = MockUser.new(:test_role)
    assert(object = TestModelSecurityModel.create)

    Authorization.current_user = MockUser.new(:test_role_restricted)
    assert_raise Authorization::NotAuthorized do
      object.update_attributes(:attr_2 => 2)
    end
  end
  
  def test_model_security_write_not_allowed_wrong_attribute_value
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role_unrestricted do
          has_permission_on :test_model_security_models do
            to :read, :create, :update, :delete
          end
        end
        role :test_role do
          has_permission_on :test_model_security_models do
            to :read, :create, :update, :delete
            if_attribute :attr => is { 1 }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)
    
    Authorization.current_user = MockUser.new(:test_role)
    assert(object = TestModelSecurityModel.create)
    assert_raise Authorization::AttributeAuthorizationError do
      TestModelSecurityModel.create :attr => 2
    end
    object = TestModelSecurityModel.create
    assert_raise Authorization::AttributeAuthorizationError do
      object.update_attributes(:attr => 2)
    end
    object.reload

    assert_nothing_raised do
      object.update_attributes(:attr_2 => 1)
    end
    assert_raise Authorization::AttributeAuthorizationError do
      object.update_attributes(:attr => 2)
    end
  end

  def test_model_security_with_and_without_find_restrictions
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role_unrestricted do
          has_permission_on :test_model_security_models do
            to :read, :create, :update, :delete
          end
        end
        role :test_role do
          has_permission_on :test_model_security_models do
            to :read, :create, :update, :delete
            if_attribute :attr => is { 1 }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    Authorization.current_user = MockUser.new(:test_role_unrestricted)
    object = TestModelSecurityModel.create :attr => 2
    object_with_find = TestModelSecurityModelWithFind.create :attr => 2
    Authorization.current_user = MockUser.new(:test_role)
    assert_nothing_raised do
      object.class.find(object.id)
    end
    assert_raise Authorization::AttributeAuthorizationError do
      object_with_find.class.find(object_with_find.id)
    end
  end

  def test_model_security_delete_unallowed
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role_unrestricted do
          has_permission_on :test_model_security_models do
            to :read, :create, :update, :delete
          end
        end
        role :test_role do
          has_permission_on :test_model_security_models do
            to :read, :create, :update, :delete
            if_attribute :attr => is { 1 }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    Authorization.current_user = MockUser.new(:test_role_unrestricted)
    object = TestModelSecurityModel.create :attr => 2
    Authorization.current_user = MockUser.new(:test_role)

    assert_raise Authorization::AttributeAuthorizationError do
      object.destroy
    end
  end

  def test_model_security_changing_critical_attribute_unallowed
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role_unrestricted do
          has_permission_on :test_model_security_models do
            to :read, :create, :update, :delete
          end
        end
        role :test_role do
          has_permission_on :test_model_security_models do
            to :read, :create, :update, :delete
            if_attribute :attr => is { 1 }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    Authorization.current_user = MockUser.new(:test_role_unrestricted)
    object = TestModelSecurityModel.create :attr => 2
    Authorization.current_user = MockUser.new(:test_role)

    # TODO before not checked yet
    #assert_raise Authorization::AuthorizationError do
    #  object.update_attributes(:attr => 1)
    #end
  end

  def test_model_security_no_role_unallowed
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
      end
    }
    Authorization::Engine.instance(reader)

    Authorization.current_user = MockUser.new(:test_role_2)
    assert_raise Authorization::NotAuthorized do
      TestModelSecurityModel.create
    end
  end

  def test_model_security_with_assoc
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_model_security_models do
            to :create, :update, :delete
            if_attribute :test_attrs => contains { user }
          end
        end
      end
    }
    Authorization::Engine.instance(reader)
    
    test_attr = TestAttr.create
    test_attr.role_symbols << :test_role
    Authorization.current_user = test_attr
    assert(object = TestModelSecurityModel.create(:test_attrs => [test_attr]))
    assert_nothing_raised do
      object.update_attributes(:attr_2 => 2)
    end
    object.reload
    assert_equal 2, object.attr_2 
    object.destroy
    assert_raise ActiveRecord::RecordNotFound do
      TestModelSecurityModel.find(object.id)
    end
  end

  def test_model_security_with_update_attrbributes
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_model_security_models, :to => :update do
            if_attribute :test_attrs => { :branch => is { user.branch }}
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    params = {
      :model_data => { :attr => 11 }
    }

    test_attr = TestAttr.create!(:branch => Branch.create!)
    test_model = without_access_control do
      TestModelSecurityModel.create!(:test_attrs => [test_attr])
    end

    with_user MockUser.new(:test_role, :branch => test_attr.branch) do
      assert_nothing_raised do
        test_model.update_attributes(params[:model_data])
      end
    end
    assert_equal params[:model_data][:attr], test_model.reload.attr

    TestAttr.delete_all
    TestModelSecurityModel.delete_all
    Branch.delete_all
  end

  def test_using_access_control
    assert !TestModel.using_access_control?
    assert TestModelSecurityModel.using_access_control?
  end

  def test_authorization_permit_association_proxy
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :test_attrs, :to => :read do
            if_attribute :test_model => {:content => "content" }
          end
        end
      end
    }
    engine = Authorization::Engine.instance(reader)

    test_model = TestModel.create(:content => "content")
    assert engine.permit?(:read, :object => test_model.test_attrs,
                          :user => MockUser.new(:test_role))
    assert !engine.permit?(:read, :object => TestAttr.new,
                          :user => MockUser.new(:test_role))
    TestModel.delete_all
  end

  def test_multiple_roles_with_has_many_through
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role_1 do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attr_throughs => contains {user.test_attr_through_id},
                :content => 'test_1'
          end
        end

        role :test_role_2 do
          has_permission_on :test_models, :to => :read do
            if_attribute :test_attr_throughs_2 => contains {user.test_attr_through_2_id},
                :content => 'test_2'
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    test_model_1 = TestModel.create! :content => 'test_1'
    test_model_2 = TestModel.create! :content => 'test_2'
    test_model_1.test_attrs.create!.test_attr_throughs.create!
    test_model_2.test_attrs.create!.test_attr_throughs.create!

    user = MockUser.new(:test_role_1, :test_role_2,
        :test_attr_through_id => test_model_1.test_attr_throughs.first.id,
        :test_attr_through_2_id => test_model_2.test_attr_throughs.first.id)
    assert_equal 2, TestModel.with_permissions_to(:read, :user => user).length
    TestModel.delete_all
    TestAttr.delete_all
    TestAttrThrough.delete_all
  end

  def test_model_permitted_to
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :companies, :to => :read do
            if_attribute :name => "company_1"
          end
        end
      end
    }
    Authorization::Engine.instance(reader)

    user = MockUser.new(:test_role)
    allowed_read_company = Company.new(:name => 'company_1')
    prohibited_company = Company.new(:name => 'company_2')

    assert allowed_read_company.permitted_to?(:read, :user => user)
    assert !allowed_read_company.permitted_to?(:update, :user => user)
    assert !prohibited_company.permitted_to?(:read, :user => user)

    executed_block = false
    allowed_read_company.permitted_to?(:read, :user => user) do
      executed_block = true
    end
    assert executed_block

    executed_block = false
    prohibited_company.permitted_to?(:read, :user => user) do
      executed_block = true
    end
    assert !executed_block

    assert_nothing_raised do
      allowed_read_company.permitted_to!(:read, :user => user)
    end
    assert_raise Authorization::NotAuthorized do
      prohibited_company.permitted_to!(:update, :user => user)
    end
    assert_raise Authorization::AttributeAuthorizationError do
      prohibited_company.permitted_to!(:read, :user => user)
    end
  end

  def test_model_permitted_to_with_modified_context
    reader = Authorization::Reader::DSLReader.new
    reader.parse %{
      authorization do
        role :test_role do
          has_permission_on :companies, :to => :read
        end
      end
    }
    Authorization::Engine.instance(reader)

    user = MockUser.new(:test_role)
    allowed_read_company = SmallCompany.new(:name => 'small_company_1')

    assert allowed_read_company.permitted_to?(:read, :user => user)
    assert !allowed_read_company.permitted_to?(:update, :user => user)
  end
end
