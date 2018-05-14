/*
 * Common JS definitions
 */
Math.radians = function(degrees) {
    return degrees * Math.PI / 180;
};

// Converts from radians to degrees.
Math.degrees = function(radians) {
    return radians * 180 / Math.PI;
};

// Switchable form fields
function selectSwitch(selector) {
  var select = $(selector),
      init_field_selector = '*[data-switchtag="' + select.val() + '"]';
  $(init_field_selector).removeClass('hidden');
  select.change(function() {
    var all_field_selector = '*[data-switchtag]',
        cur_field_selector = '*[data-switchtag="' + select.val() + '"]';
    $(all_field_selector).addClass('hidden');
    $(cur_field_selector).removeClass('hidden');
  });
};

$(document).ready(function() {
    if (location.hash) {
        $("a[data-tabcode='" + location.hash + "']").tab("show");
    }
    $(document.body).on("click", "a[data-toggle]", function(event) {
        location.hash = this.getAttribute("data-tabcode");
    });

    // Hide flash message after 7 seconds
    setTimeout(function () {
      $(".alert.fade").alert('close');
    }, 7000);

    $.validator.addMethod('uuid', validateFieldIsUuid, 'Entered value is not a valid UUID.');
});

$(window).on("popstate", function() {
    var anchor = location.hash;
    if (location.hash) {
        $("a[data-tabcode='" + anchor + "']").tab("show");
    }
});
