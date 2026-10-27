use revolt_rocket_okapi::revolt_okapi::openapi3::OpenApi;
use rocket::Route;

mod event_create;
mod event_delete;
mod event_edit;
mod event_fetch;
mod event_guests;
mod event_list;
mod event_saved;

pub fn routes() -> (Vec<Route>, OpenApi) {
    openapi_get_routes_spec![
        event_create::create_event,
        event_delete::delete_event,
        event_edit::update_event,
        event_fetch::get_event,
        event_list::list_events,
        event_saved::toggle_saved_event,
        event_saved::get_saved_events,
        event_list::get_created_events,
        event_guests::add_guest,
        event_guests::get_event_guests,
        event_guests::get_registration_contact,
        event_guests::get_guest,
        event_guests::add_bulk_guests,
        event_guests::update_bulk_guest_status,
        event_guests::send_bulk_messages,
        event_guests::notify_guests,
    ]
}
