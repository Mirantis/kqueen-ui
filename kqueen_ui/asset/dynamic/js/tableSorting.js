function setUpSorting() {
  $(document).on('click', '.sort-column-btn .mdi-arrow-up-bold', function() {
    var [target, value] = $(this).parent().attr('name').split('_');
    updateSortingParam(target, value, 'asc');
  });
  $(document).on('click', '.sort-column-btn .mdi-arrow-down-bold', function() {
    var [target, value] = $(this).parent().attr('name').split('_');
    updateSortingParam(target, value, 'desc');
  });
}

function handleSortingView(target, sortingKey, sortingOrder, queryParams) {
  // Enable either up or down arrow depending on corresponding query parameters
  if (sortingKey in queryParams) {
    var sortingRoot = $(`a[name=${target}_${queryParams[sortingKey]}]`);
    var isDesc = !(sortingOrder in queryParams && queryParams[sortingOrder] === 'asc');
    sortingRoot.find('i.mdi').eq(isDesc ? 0 : 1).addClass('active');
  }
}
