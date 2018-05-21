function fieldList() {
  $('div[id$=fieldset]').each(function () {
    var $this = $(this);
    //  Hide button that can remove last tr
    $this.find('[data-toggle=fieldset-entry] td:last').hide();

    // Add new entry
    $this.find('button[id$=fieldset-add-row]').click(function () {
      var lastRow = $this.find('[data-toggle=fieldset-entry]:last');
      var newRow = lastRow.clone(true, true);

      var newElemID = newRow.find(':input')[0].id;
      // Get new newRow id: search for serial number in the old newRow id, convert and increment it
      var elemNum = parseInt(newElemID.replace(/.*-(\d{1,4})-.*/, '$1')) + 1;
      newRow.attr('data-id', elemNum);
      newRow.find(':input').each(function () {

        var id = $(this).attr('id').replace('-' + (elemNum - 1) + '-', '-' + (elemNum) + '-');
        $(this).attr('name', id).attr('id', id).val('');
      });
      newRow.find('td:last').show();
      lastRow.after(newRow);
    });

    // Remove row
    $this.find('button[id$=remove-row]').click(function () {
      if ($this.find('[data-toggle=fieldset-entry]').length > 1) {
        var row = $(this).closest('[data-toggle=fieldset-entry]');
        row.remove();
      }
    });
  });
};
window.onload = fieldList;
