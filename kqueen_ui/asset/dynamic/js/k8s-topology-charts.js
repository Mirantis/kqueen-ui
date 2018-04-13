 /**
 * Module with K8SVisualisations main init
 */
var K8SVisualisations = (K8SVisualisations = {}) => {
  K8SVisualisations.init = (topologyDataURL) => {
     // init Isotope
    $(document).one('shown.bs.tab', 'a[href="#addons"]', (e) => {
      var $grid = $('.grid').isotope({
        itemSelector: '.addon-item',
        layoutMode: 'fitRows'
      });
      $('.grid').each(() => {
        var $grid = $(this);
        $grid.css('min-height', $grid.innerHeight());
      });
      // bind filter button click
      $('#filters').on('click', 'a', (ev) => {
      ev.preventDefault();
      var filterValue = $(this).attr('data-filter');
        $grid.isotope({filter: filterValue});
      });
    });

    $(() => {
      // bind click actions
      $('#ForcedLayoutGraphBtn').on('click', (e) => {
        $('#HiveGraphContainer').css('z-index', '1').css('pointer-events', 'none');
        $('#ForcedLayoutGraphContainer').css('z-index', '2').css('pointer-events', 'all');
        $('#HiveGraphBtn').removeClass('active');
        $('#ForcedLayoutGraphBtn').addClass('active');
      });

      $('#HiveGraphBtn').on('click', (e) => {
        $('#ForcedLayoutGraphContainer').css('z-index', '1').css('pointer-events', 'none');
        $('#HiveGraphContainer').css('z-index', '2').css('pointer-events', 'all');
        $('#ForcedLayoutGraphBtn').removeClass('active')
        $('#HiveGraphBtn').addClass('active');
      });
      $('.topology-legend svg').each(() => {
        var filterData = (data, filterState) => {
          var enabledKinds = Object
            .entries(filterState)
            .filter((i) => i[1])
            .map((i) => i[0]);
          var newItems = {};
          // filter entries by kind
          Object.entries(window._originalGraphData.items).forEach((i) => {
            if(enabledKinds.indexOf(i[1].kind) != -1) {
              newItems[i[0]] = i[1];
            }
          });
          return {
            items: newItems,
            kinds: window._originalGraphData.kinds,
            relations: window._originalGraphData.relations
          };
        };

        $(this).on('click', (e) => {
          $(e.target).parent().toggleClass('filterDisabled');
          var filterState = {};
          $('.topology-legend svg').each(() => {
            var $chbox = $(this);
            filterState[$chbox.attr('data-kind')] = !$chbox.hasClass('filterDisabled');
          });
          initCharts(filterData(window._originalGraphData, filterState));
        });
      });
    });

    var initCharts = (data) => {
      var changeDetailBox = (node) => {
        console.log(node);
        if ('item' in node) {
          $('#resource-detail').html(
            '<dl><dt>Name</dt><dd>' + node.item.metadata.name +
            '</dd><dt>Kind</dt><dd>' + node.item.kind +
            '</dd><dt>Namespace</dt><dd>' + node.item.metadata.namespace + '</dd></dl>'
          );
        } else {
          $('#resource-detail').html(
            '<dl><dt>Name</dt><dd>' + node.metadata.name +
            '</dd><dt>Kind</dt><dd>' + node.kind +
            '</dd><dt>Namespace</dt><dd>' + node.metadata.namespace + '</dd></dl>'
          );
        }
      };
      if (data) {
        window._graphData = data;
      }
      K8SVisualisations.forcedChart.init(
        '#topology-graph',
        $.extend({}, window._graphData),
        {nodeClickFn: changeDetailBox}
      );
      K8SVisualisations.hiveChart.init(
        '#HiveChart',
        $.extend({}, window._graphData),
        {nodeClickFn: changeDetailBox}
      );
      $('#HiveGraphBtn, #ForcedLayoutGraphBtn').attr('disabled', false);
    };

    $(document).one('shown.bs.tab', 'a[href="#topology"]', (e) => {
      d3.json(topologyDataURL, (data) => {
        window._originalGraphData = data;
        initCharts(data);
      });
    });
  };
  return K8SVisualisations;
}(K8SVisualisations || {});
