#!/bin/bash

# OID4VC Integration Test Runner
# Provides easy commands for running different test configurations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to cleanup containers
cleanup() {
    print_info "Cleaning up containers and volumes..."
    docker compose down -v 2>/dev/null || true
    docker compose -f docker-compose.full.yml down -v 2>/dev/null || true
    docker compose -f docker-compose.dev.yml down -v 2>/dev/null || true
    print_success "Cleanup complete"
}

# Function to purge docker resources
purge() {
    cleanup
    print_info "Purging all unused Docker resources (images, containers, networks, volumes)..."
    print_warning "This will remove all stopped containers, all networks not used by at least one container, all dangling images, and all build cache."
    
    docker system prune -a --volumes -f
    print_success "Docker purge complete"
}

# Function to check Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker Desktop and try again."
        exit 1
    fi
}

# Show usage
show_usage() {
    echo "OID4VC Integration Test Runner"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  quick          Run quick validation tests (3 tests, ~30s)"
    echo "  full           Run comprehensive test suite (39 tests, ~5-10min)"
    echo "  dev            Start development environment (services only)"
    echo "  test <name>    Run specific test file in dev environment"
    echo "  logs <service> Show logs for specific service"
    echo "  clean          Clean up all containers and volumes"
    echo "  purge          Deep clean (prune) all unused Docker resources"
    echo "  status         Show status of running services"
    echo ""
    echo "Examples:"
    echo "  $0 quick                           # Fast validation"
    echo "  $0 full                            # Complete test suite"
    echo "  $0 dev                             # Start dev environment"
    echo "  $0 test test_docker_connectivity   # Run specific test"
    echo "  $0 logs credo-agent                # Show Credo agent logs"
    echo "  $0 clean                           # Clean up everything"
    echo "  $0 purge                           # Deep clean to free space"
    echo ""
}

# Quick tests (default docker-compose.yml)
run_quick() {
    print_info "Running quick validation tests..."
    print_info "This will run 3 essential tests: connectivity + basic flow"
    
    cleanup
    docker compose up --build --abort-on-container-exit
    
    if [ $? -eq 0 ]; then
        print_success "Quick tests completed successfully!"
    else
        print_error "Quick tests failed!"
        exit 1
    fi
}

# Full comprehensive tests
run_full() {
    print_info "Running comprehensive test suite..."
    print_info "This will run all 39+ tests and may take 5-10 minutes"
    
    cleanup
    docker compose -f docker-compose.full.yml up --build --abort-on-container-exit
    
    if [ $? -eq 0 ]; then
        print_success "Full test suite completed successfully!"
        print_info "Test results available in test-results/ directory"
    else
        print_warning "Some tests may have failed. Check test-results/ for details"
        exit 1
    fi
}

# Development environment
run_dev() {
    print_info "Starting development environment..."
    print_info "Services will run in background. Use 'docker compose -f docker-compose.dev.yml exec integration-tests bash' to access test container"
    
    cleanup
    docker compose -f docker-compose.dev.yml up -d --build
    
    if [ $? -eq 0 ]; then
        print_success "Development environment started!"
        print_info "Services running:"
        print_info "  - Credo Agent: http://localhost:3020"
        print_info "  - ACA-Py Issuer Admin: http://localhost:8021"
        print_info "  - ACA-Py Verifier Admin: http://localhost:8031"
        print_info ""
        print_info "To run tests manually:"
        print_info "  docker compose -f docker-compose.dev.yml exec integration-tests uv run pytest tests/ -v"
        print_info ""
        print_info "To stop services:"
        print_info "  docker compose -f docker-compose.dev.yml down"
    else
        print_error "Failed to start development environment!"
        exit 1
    fi
}

# Run specific test
run_test() {
    local test_name=$1
    if [ -z "$test_name" ]; then
        print_error "Please specify a test name"
        show_usage
        exit 1
    fi
    
    print_info "Running test: $test_name"
    
    # Check if dev environment is running
    if ! docker compose -f docker-compose.dev.yml ps | grep -q "Up"; then
        print_info "Starting development environment first..."
        docker compose -f docker-compose.dev.yml up -d --build
        sleep 10
    fi
    
    docker compose -f docker-compose.dev.yml exec integration-tests uv run pytest "tests/${test_name}.py" -v -s
}

# Show logs
show_logs() {
    local service=$1
    if [ -z "$service" ]; then
        print_error "Please specify a service name (credo-agent, acapy-issuer, acapy-verifier, integration-tests)"
        exit 1
    fi
    
    print_info "Showing logs for $service..."
    
    # Try different compose files
    if docker compose ps | grep -q "$service"; then
        docker compose logs -f "$service"
    elif docker compose -f docker-compose.full.yml ps | grep -q "$service"; then
        docker compose -f docker-compose.full.yml logs -f "$service"
    elif docker compose -f docker-compose.dev.yml ps | grep -q "$service"; then
        docker compose -f docker-compose.dev.yml logs -f "$service"
    else
        print_error "Service $service not found or not running"
        exit 1
    fi
}

# Show status
show_status() {
    print_info "Service Status:"
    echo ""
    
    echo "Default environment:"
    docker compose ps 2>/dev/null || echo "  Not running"
    echo ""
    
    echo "Full test environment:"
    docker compose -f docker-compose.full.yml ps 2>/dev/null || echo "  Not running"
    echo ""
    
    echo "Development environment:"
    docker compose -f docker-compose.dev.yml ps 2>/dev/null || echo "  Not running"
}

# Main script logic
main() {
    check_docker
    
    case "${1:-}" in
        "quick"|"")
            run_quick
            ;;
        "full")
            run_full
            ;;
        "dev")
            run_dev
            ;;
        "test")
            run_test "$2"
            ;;
        "logs")
            show_logs "$2"
            ;;
        "clean")
            cleanup
            ;;
        "purge")
            purge
            ;;
        "status")
            show_status
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            print_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"