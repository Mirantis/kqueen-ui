/**
 * Module with K8SVisualisations forced chart
 */
var K8SVisualisations = ((K8SVisualisations = {}) => {
  K8SVisualisations.forcedChart = K8SVisualisations.forcedChart || {};

  K8SVisualisations.forcedChart.init = (selector, data, config = {}) => {
    K8SVisualisations.forcedChart.cache = {};
    if (!data) {
      throw new Error(
        'Cannot init K8S forced layout chart visualisation, invalid data given ' + data
      );
    }
    var element = d3.select(selector),
        kinds = {
          Pod: '#vertex-Pod',
          ReplicationController: '#vertex-ReplicationController',
          Node: '#vertex-Node',
          Service: '#vertex-Service',
          ReplicaSet: '#vertex-ReplicaSet',
          Container: '#vertex-Container',
          Deployment: '#vertex-Deployment',
          Namespace: '#vertex-Namespace'
        };

    var graph = K8SVisualisations.forcedChart.constructChart(selector, {kinds: kinds});
    graph.render(graph.data(data.items, data.relations), config);
    graph.select();
  };

  K8SVisualisations.forcedChart.constructChart = (selector, options) => {
    var outer = d3.select(selector);
    outer.html('');
    var kinds = options.kinds; // Kinds of objects to show
    var items = [], relations = []; // Data we've been fed
    var width, height, radius = 20; // Graph information
    if (options.radius) {
       radius = options.radius;
    }
    var timeout;
    var nodes = [], links = [];
    var lookup = {};
    var selection = null;
    var force = options.force;

    // Allow the force to be passed in, default if not
    if (!force) {
      force = d3.layout.force().charge(-60).linkDistance(100);
    }

    var drag = force.drag();

    var svg = outer
      .append('svg')
      .attr('viewBox', '0 0 1600 1200')
      .attr('preserveAspectRatio', 'xMidYMid meet')
      .attr('class', 'kube-topology');
    var mouseFunctions = {
      linkOver: (d) => {
        svg.selectAll('line').classed('active', (p) => p === d);
        svg.selectAll('.node circle').classed('active', (p) => {
          return p === d.source || p === d.target;
        });
        svg.selectAll('.node text').classed('active', (p) => {
          return p === d.source || p === d.target;
        });
      },
      nodeOver: (d) => {
        svg.selectAll('line').classed('active', (p) => {
          return p.source === d || p.target === d;
        });
        d3.select(this).select('circle').classed('active', true);
        d3.select(this).select('text').classed('active', true);
      },
      out: (d) => {
        svg.selectAll('.active').classed('active', false);
      }
    };
    // null values here
    var vertices = d3.select();
    var edges = d3.select();
    force.on('tick', () => {
      edges
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y);

      vertices
        .attr('cx', (d) => {
          d.x = d.fixed ? d.x : Math.max(radius, Math.min(width - radius, d.x));
          return d.x;
        })
        .attr('cy', (d) => {
          d.y = d.fixed ? d.y : Math.max(radius, Math.min(height - radius, d.y));
          return d.y;
        })
        .attr('transform', (d) => `translate(${d.x}, ${d.y})`);
    });

    drag
      .on('dragstart', (d) => {
        select(d.item);

        if (!d.fixed) {
          d.floatpoint = [d.x, d.y];
        }
        d.fixed = true;
        d3.select(this).classed('fixed', true);
      })
      .on('dragend', (d) => {
        var moved = true;
        if (d.floatpoint) {
          var point1 = d.floatpoint[0], point2 = d.floatpoint[1];
          moved = (d.x < point1 - 5 || d.x > point1 + 5) || (d.y < point2 - 5 || d.y > point2 + 5);
          delete d.floatpoint;
        }
        d.fixed = moved && d.x > 3 && d.x < (width - 3) && d.y >= 3 && d.y < (height - 3);
        d3.select(this).classed('fixed', d.fixed);
      });

    svg.on('dblclick', () => {
      svg
        .selectAll('g')
        .classed('fixed', false)
        .each((d) => (d.fixed = false));
      force.start();
    });

    function select(item) {
      selection = item;
      svg
        .selectAll('g')
        .classed('selected', (d) => d.item === item);
    }

    function adjust() {
      timeout = null;
      width = outer.node().clientWidth;
      height = outer.node().clientHeight;

      force.size([width, height]);
      svg.attr('viewBox', `0 0 ${width} ${height}`);
      update();
    }

    function update() {
      edges = svg.selectAll('line').data(links);

      edges.exit().remove();
      edges.enter().insert('line', ':first-child');
      edges.attr('class', (d) => d.kinds);
      edges
        .on('mouseover', mouseFunctions.linkOver)
        .on('mouseout', mouseFunctions.out);

      vertices = svg.selectAll('g').data(nodes, (d) => d.id);
      vertices.on('mouseover', mouseFunctions.nodeOver).on('mouseout', mouseFunctions.out);
      vertices.exit().remove();

      var added = vertices.enter().append('g').call(drag);
      select(selection);
      force.nodes(nodes).links(links).start();
      return added;
    }

    function digest() {
      var pnodes = nodes;
      var plookup = lookup;

      // The actual data for the graph
      nodes = [];
      links = [];
      lookup = { };

      var item, id, kind, node;
      for (id in items) {
        item = items[id];
        kind = item.kind;

        if (kinds && !kinds[kind]) {
          continue;
        }

        // Prevents flicker
        node = pnodes[plookup[id]];
        if (!node) {
          node = K8SVisualisations.forcedChart.cache[id];
          delete K8SVisualisations.forcedChart.cache[id];
          if (!node) {
            node = {};
          }
        }

        node.id = id;
        node.item = item;

        lookup[id] = nodes.length;
        nodes.push(node);
      }

      var i, len, relation, source, target;
      for (i = 0, len = relations.length; i < len; i++) {
        relation = relations[i];

        source = lookup[relation.source];
        target = lookup[relation.target];
        if (source === undefined || target === undefined) {
          continue;
        }

        links.push({source, target, kinds: nodes[s].item.kind + nodes[t].item.kind});
      }

      return width && height ? update() : d3.select();
    }

    function resized() {
      window.clearTimeout(timeout);
      timeout = window.setTimeout(adjust, 150);
    }
    window.addEventListener('resize', resized);
    adjust();
    resized();

    return {
      select,
      kinds: (value) => {
        kinds = value;
        var added = digest();
        return [vertices, added];
      },
      data: (new_items, new_relations) => {
        items = new_items || { };
        relations = new_relations || [];
        var added = digest();
        return [vertices, added];
      },
      render: (graphData, config = {}) => {
        var vertices = graphData[0];
        var added = graphData[1];

        added.attr('class', (d) => d.item.kind);
        added.append('use').attr('xlink:href', (d) => kinds[d.item.kind]);
        added.append('title');
        if(config.hasOwnProperty('nodeClickFn') && typeof config.nodeClickFn === 'function') {
          vertices.on('click', config.nodeClickFn);
        }
        vertices
          .selectAll('title')
          .text((d) => d.item.metadata.name);

        vertices.classed('weak', (d) => {
          var status = d.item.status;
          return status && status.phase && status.phase !== 'Running';
        });
      },
      close: () => {
        window.removeEventListener('resize', resized);
        window.clearTimeout(timeout);

        /*
         * Keep the positions of these items cached,
         * in case we are asked to make the same graph again.
         */
        var id, node;
        K8SVisualisations.forcedChart.cache = {};
        for (id in lookup) {
          node = nodes[lookup[id]];
          delete node.item;
          K8SVisualisations.forcedChart.cache[id] = node;
        }

        nodes = [];
        lookup = {};
      }
    };
  };

  return K8SVisualisations;
})(K8SVisualisations || {});
