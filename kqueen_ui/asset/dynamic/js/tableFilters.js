function serializeToQueryString(params) {
  if (jQuery.isEmptyObject(params)) {
    return '';
  }
  var queryStrings = [];
  for (var key in params) {
    if (params.hasOwnProperty(key) && params[key]) {
      queryStrings.push(encodeURIComponent(key) + '=' + encodeURIComponent(params[key]));
    }
  }
  return '?' + queryStrings.join('&');
}

function getQueryParameters() {
  var pageQueryString = window.location.search.substring(1),
      params = pageQueryString.split('&');
  if (!pageQueryString) {
    return {};
  }
  var parsed = {};
  for (var paramString of params) {
    var [key, value] = paramString.split('=');
    parsed[decodeURIComponent(key)] = decodeURIComponent(value);
  }
  return parsed;
}

function setQueryParameters(params) {
  var queryString = serializeToQueryString(params);
  if (queryString) {
    window.history.pushState('newState', '', queryString);
  }
}

function showFilterIcon(filterRoot) {
  // Hide filter value and clear button
  filterRoot.find('span.filter-value').addClass('hidden');
  filterRoot.find('.clear-filter-value').addClass('hidden');

  // Show filter icon
  filterRoot.find('i.mdi-filter').removeClass('hidden');
}

function showFilterValue(filterRoot, queryParams, name) {
  // Hide filter icon
  filterRoot.find('div.filter-icon i.mdi-filter').addClass('hidden');

  // Show filter value and clear button
  var value = queryParams[name];
  filterRoot.find('div.filter-icon span.filter-value').removeClass('hidden').text(value);
  filterRoot.find('.clear-filter-value').removeClass('hidden');

  // Paste the value into popover input
  $(`input[name=${name}]`).val(value);
}

function handleFilterView(filterNames, queryParams) {
  // Show either icon or value depending on corresponding query parameters
  for (var filterName of filterNames) {
    var filterRoot = $(`div.js-${filterName}`);
    if (filterName in queryParams && queryParams[filterName]) {
      showFilterValue(filterRoot, queryParams, filterName);
    } else {
      showFilterIcon(filterRoot);
    }
  }
}

function handlePopoverDisplaying() {
  $(document).on('click', '[data-toggle="popover"]', function() {
    var popover = $(this).parent().find('.filtering-popover');
    if (popover.hasClass('preserved-popover')) {
      popover.find('input').blur();
      popover.removeClass('preserved-popover');
    } else {
      popover.addClass('preserved-popover');
      popover.find('input').focus();
    }
  });

  $(document).on('focusout', '.filtering-popover', function() {
    if (!($('.filtering-popover:hover').length ||
          $(this).parent().find('[data-toggle="popover"]:hover').length)) {
      $(this).removeClass('preserved-popover');
    }
  });

  $(document).on('click', '.clear-filter-value', function(e) {
    e.stopPropagation();

    // Reset the filter
    var filterRoot = $(this).parents('div[data-toggle=popover]').parent(),
        filterName = filterRoot.attr('class').slice('js-'.length),
        target = filterName.startsWith('cluster') ? 'cluster' : 'provisioner';
    updateFilterParam(target, {[filterName]: ''});
  });
}
