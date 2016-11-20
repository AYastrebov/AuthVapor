import Vapor
import HTTP
import Turnstile
import VaporPostgreSQL

final class UserController: ResourceRepresentable {
    
    func index(request: Request) throws -> ResponseRepresentable {
        return try User.all().toJSON()
    }
    
    func show(request: Request, user: User) throws -> ResponseRepresentable {
        return user
    }
    
    func create(request: Request) throws -> ResponseRepresentable {
        var user = try request.user()
        try user.save()
        return user
    }
    
    func update(request: Request, user: User) throws -> ResponseRepresentable {
        let new = try request.user()
        var user = user
        user.merge(updates: new)
        try user.save()
        return user
    }
    
    func delete(request: Request, user: User) throws -> ResponseRepresentable {
        try user.delete()
        return user
    }
    
    func makeResource() -> Resource<User> {
        return Resource(
            index: index,
            store: create,
            show: show,
            modify: update,
            destroy: delete
        )
    }
}

extension Request {
    // Helper method to get the current user
    func user() throws -> User {
        guard let user = try auth.user() as? User else {
            throw UnsupportedCredentialsError()
        }
        return user
    }
    
    // Base URL returns the hostname, scheme, and port in a URL string form.
    var baseURL: String {
        return uri.scheme + "://" + uri.host + (uri.port == nil ? "" : ":\(uri.port!)")
    }
    
    // Exposes the Turnstile subject, as Vapor has a facade on it.
    var subject: Subject {
        return storage["subject"] as! Subject
    }
}
