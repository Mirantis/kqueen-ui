function handleBulkDelete(
  selectAllCheckboxSelector, rowCheckboxesSelector, buttonSelector, 
  formTargetUrl, targetName
) {
  var selectAllCheckbox = $(selectAllCheckboxSelector),
      activeRowCheckboxes = $(rowCheckboxesSelector + ':not(:disabled)'),
      bulkDeleteButton = $(buttonSelector);
  var checkedRowsSelector = rowCheckboxesSelector + ':checked',
      notCheckedRowsSelector = rowCheckboxesSelector + ':not(:checked)';

  var isZeroCount = (selector) => !$(selector).get().length;
  var setDeleteButtonState = (enable) => {
    // "disabled" prop is not allowed for anchors, so a class is used instead
    enable ? bulkDeleteButton.removeClass('disabled') : bulkDeleteButton.addClass('disabled');
  }
  var getSelectedObjectsNames = () => $(checkedRowsSelector).map(function() {
    return this.value;
  }).get();
  var getSelectedObjectsIds = () => $(checkedRowsSelector).map(function() {
    return this.name;
  }).get();
  var setButtonTarget = () => {
    bulkDeleteButton.data('target', formTargetUrl(getSelectedObjectsIds().join('+')));
    var names = getSelectedObjectsNames();
    var confirmationText = (
      isZeroCount(notCheckedRowsSelector) ?
      `ALL your ${targetName}s (${names.join(', ')})` :
      `${targetName}${names.length === 1 ? '' : 's'} ${names.join(', ')}`
    );
    bulkDeleteButton.data('name', confirmationText);
  }

  // Disable select-all checkbox if all others are disabled
  if (isZeroCount(activeRowCheckboxes)) {
    selectAllCheckbox.prop('disabled', true);
    var checkboxLabel = $(selectAllCheckbox.next('label')[0]);
    checkboxLabel.addClass('disabled-wrapper');
    $(checkboxLabel.find('.checkbox-all')[0]).addClass('disabled');
  }

  // Checkboxes will be still selected if e.g. you open cluster page and then go back,
  // so in this case delete button should be enabled
  if (!isZeroCount(checkedRowsSelector)) {
    setDeleteButtonState(activeRowCheckboxes.is(':checked'));
    setButtonTarget();
  }

  selectAllCheckbox.bind('change', function () {
    var selectAllChecked = selectAllCheckbox.is(':checked');
    activeRowCheckboxes.prop('checked', selectAllChecked);
    setDeleteButtonState(selectAllChecked);
    if (selectAllChecked) {
      setButtonTarget();
    }
  });
  activeRowCheckboxes.bind('change', function () {
    setDeleteButtonState(activeRowCheckboxes.is(':checked'));
    setButtonTarget();
    if (isZeroCount(notCheckedRowsSelector)) {
      selectAllCheckbox.prop('checked', true).trigger('change');
    } else if (isZeroCount(checkedRowsSelector)) {
      selectAllCheckbox.prop('checked', false).trigger('change');
    }
  });

  // Handle table row click
  $('tr.clickable').click(function(e) {
    if (e.target.tagName === 'TD') {
      var rowCheckbox = $($(e.target).parent().find(activeRowCheckboxes)[0]);
      rowCheckbox.prop('checked', !rowCheckbox.is(':checked')).trigger('change');
    }
  });
}

