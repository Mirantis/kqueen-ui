/*
 * Common JS definitions
 */
Math.radians = (degrees) => degrees * Math.PI / 180;

// Converts from radians to degrees.
Math.degrees = (radians) => radians * 180 / Math.PI;

// Switchable form fields
function selectSwitch(selector) {
  var select = $(selector);
  var init_field_selector = `*[data-switchtag="${select.val()}"]`;
  $(init_field_selector).removeClass('hidden');
  select.change(() => {
    var all_field_selector = '*[data-switchtag]';
    var cur_field_selector = `*[data-switchtag="${select.val()}"]`;
    $(all_field_selector).addClass('hidden');
    $(cur_field_selector).removeClass('hidden');
  });
};

$(document).ready(() => {
  if (location.hash) {
    $(`a[data-tabcode="${location.hash}"]`).tab('show');
  }
  $(document.body).on('click', 'a[data-toggle]', (event) => {
    location.hash = this.getAttribute('data-tabcode');
  });

  // Hide flash message after 3 seconds
  setTimeout(() => {
    $('.alert.fade').alert('close');
  }, 3000);

  $.validator.addMethod(
    'uuid',
    (value, element, condition) => {
      var pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      var result  = pattern.test(value)
      return this.optional(element) || result === condition
    },
    'Entered value is not a valid UUID.'
  );
});

$(window).on('popstate', () => {
  var anchor = location.hash;
  if (location.hash) {
    $(`a[data-tabcode="${anchor}"]`).tab('show');
  }
});
