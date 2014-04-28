'use strict';

module.exports.parse = function (json) {
  var profile = {};

  profile.id = json.id;

  profile.displayName = json.first_name + ' ' + json.last_name;
  profile.name = { familyName: json.last_name,
                   givenName: json.first_name };
  profile.emails = [{ value: json.email }];

  return profile;
};
