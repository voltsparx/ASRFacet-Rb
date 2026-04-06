# Part of ASRFacet-Rb — authorized testing only
require "time"

module ASRFacet
  module Core
    class KnowledgeGraph
      def initialize
        @nodes = {}
        @edges = Hash.new { |hash, key| hash[key] = [] }
        @mutex = Mutex.new
      end

      def add_node(id, type:, data: {})
        node_id = id.to_s
        return nil if node_id.empty?

        @mutex.synchronize do
          @nodes[node_id] = {
            id: node_id,
            type: type.to_sym,
            data: data.is_a?(Hash) ? data : {},
            discovered_at: Time.now.iso8601
          }
        end
      rescue StandardError
        nil
      end

      def add_edge(from_id, to_id, relation:)
        source = from_id.to_s
        target = to_id.to_s
        return nil if source.empty? || target.empty?

        edge = { to: target, relation: relation.to_sym }
        @mutex.synchronize do
          @edges[source] << edge unless @edges[source].any? { |entry| entry[:to] == target && entry[:relation] == relation.to_sym }
        end
        edge
      rescue StandardError
        nil
      end

      def neighbors(id)
        pivot(id)[:neighbors]
      rescue StandardError
        []
      end

      def pivot(id)
        node_id = id.to_s
        @mutex.synchronize do
          related_edges = flattened_edges.select { |edge| edge[:from] == node_id || edge[:to] == node_id }
          {
            node: @nodes[node_id],
            edges: related_edges,
            neighbors: related_edges.filter_map do |edge|
              neighbor_id = edge[:from] == node_id ? edge[:to] : edge[:from]
              @nodes[neighbor_id]
            end.uniq
          }
        end
      rescue StandardError
        { node: nil, edges: [], neighbors: [] }
      end

      def subgraph(type:)
        node_type = type.to_sym
        @mutex.synchronize do
          nodes = @nodes.values.select { |node| node[:type] == node_type }
          ids = nodes.map { |node| node[:id] }
          {
            nodes: nodes,
            edges: flattened_edges.select { |edge| ids.include?(edge[:from]) || ids.include?(edge[:to]) }
          }
        end
      rescue StandardError
        { nodes: [], edges: [] }
      end

      def to_h
        @mutex.synchronize do
          {
            nodes: @nodes.values,
            edges: flattened_edges
          }
        end
      rescue StandardError
        { nodes: [], edges: [] }
      end

      private

      def flattened_edges
        @edges.each_with_object([]) do |(from, entries), memo|
          entries.each do |entry|
            memo << { from: from, to: entry[:to], relation: entry[:relation] }
          end
        end
      rescue StandardError
        []
      end
    end
  end
end
