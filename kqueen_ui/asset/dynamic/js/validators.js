function validateFileField(element, requiredKeys, parser, validationFailedMessage) {
  var data = 'error',
      message = 'Validation failed',
      isValid = false;
  try {
    data = parser(element.value);
  } catch(err) {
    var message = err.reason || err.message;
    message = validationFailedMessage + (message ? (' (' + message + ')') : '');
    console.log(err);
  }
  if (!(data instanceof Object)) {
    if (message === 'Validation failed') {
      message = validationFailedMessage;
    }
  } else {
    var missingKeys = [],
        countKeys = 0;
    requiredKeys.forEach(function(key) {
      if (key in data) {
        countKeys++;
      } else {
        missingKeys.push(key);
      }
    });
    if (countKeys !== requiredKeys.length) {
      message = 'Missing mandatory keys: ' + missingKeys.join(', ');
    } else {
      isValid = true;
    }
  }
  var validator = $("#switchableForm").data().validator;
  if (isValid) {
      $(element).parent().parent('.form-group').removeClass('has-error');
      var submitted = validator.formSubmitted;
      validator.resetInternals();
      validator.toHide = validator.errorsFor(element);
      validator.formSubmitted = submitted;
      validator.successList.push(element);
      validator.invalid[element.name] = false;
      validator.showErrors();
  } else {
      $(element).parent().parent('.form-group').addClass('has-error');
      var errors = {[element.name]: message};
      validator.invalid[element.name] = true;
      validator.showErrors(errors);
  }
  validator.stopRequest(element, isValid);
  return 'pending';
}

function validateJsonFileField(value, element, requiredKeys) {
  return validateFileField(element, requiredKeys, (d) => JSON.parse(d), 'Not a valid JSON');
}

function validateYamlFileField(value, element, requiredKeys) {
  return validateFileField(element, requiredKeys, (d) => jsyaml.safeLoad(d), 'Not a valid YAML');
}

function validateFieldIsIpCidr(value, element, regexp) {
  var regexp = new RegExp(
    '^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}' +
    '([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])' +
    '(/([0-9]|[1-9][0-9]|2[0-4]))?)?$'
  );
  return regexp.test(value);
}

function validateFieldIsUuid(value, element, condition) {
  var regexp = new RegExp(
    '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', 'i'
  );
  // Immediately return true if the element is blank AND it is not required
  return this.optional(element) || regexp.test(value) === condition;
}

function validateFieldParity(value, element, parityChecker) {
  var parity = value % 2;
  return parityChecker === 'odd' ? parity : parityChecker === 'even' ? !parity : false;
}

function validateFieldIsListOfIps(value, element, condition) {
  // Do not validate empty and optional element
  // this.optional is false when it is not empty
  if (this.optional(element) != false) {
    return true;
  };

  var regexp = new RegExp(
    '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.' +
    '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', 'i'
  );
  var arr = value.split(",");
  for (var ip of arr) {
     if (regexp.test(ip.trim()) !== condition) {
      return false;
     }
  }
  return true;
}
