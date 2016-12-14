Original docs: [https://github.com/stffn/declarative_authorization/blob/master/README.rdoc](https://github.com/stffn/declarative_authorization/blob/master/README.rdoc)

### Polymorphic associations

This branch contains polymorphic belongs_to association support.
It relies on a monkey patch to active record which provides the method `poly_resources`
that returns a list of classes that the polymorphic association can point to.


### Running tests for DA

```
cp gemfiles/3.2.gemfile Gemfile
bundle

bundle exec rake test
```


