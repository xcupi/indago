-- Form-group association for discovered parameters.
--
-- One page can hold several <form> elements posting to the same action (bWAPP's
-- /commandi.php has three). Their fields are separate request shapes, not one
-- parameter list, so the group a field came from is part of its identity:
-- a request built for one field must carry only that form's fields.
ALTER TABLE parameters ADD COLUMN form_group TEXT NOT NULL DEFAULT '';
