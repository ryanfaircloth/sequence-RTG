#
class { 'patterndb':
  manage_package => false,
  base_dir => '/tmp'
}

patterndb::simple::ruleset { 'promoted':
  id => '8dffd37a-0602-4ba8-88a5-cf5490dbf629',
  patterns => ['sshd'],
  pubdate => '2019-04-16',
  rules => [
    {
      id => '122a981f-5c80-4044-8c21-50174c2ce70f',
      provider => 'wernli@in2p3.fr',
      patterns => [ 'this', 'this@ANYSTRING:promoted:@' ],
      examples => [ { program => 'sshd', test_message => 'this is a message which we know very well'} ],
      ruleclass => 'promoted',
    }
  ]
}

patterndb::simple::ruleset { 'generated':
  id => '5be2a930-7a0f-4ef4-9224-e49c4b27408b',
  patterns => ['sshd'],
  pubdate => '2019-04-16',
  rules => [
    {
      id => '9c094449-c96a-4e96-929b-b6c448360e64',
      provider => 'wernli@in2p3.fr',
      patterns => [ 'that', 'that@ANYSTRING:generated:@' ],
      examples => [ { program => 'sshd', test_message => 'that is an interesting message'} ],
      ruleclass => 'generated',
    }
  ]
}

