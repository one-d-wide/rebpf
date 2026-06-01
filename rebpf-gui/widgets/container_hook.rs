use iced_core::layout;
use iced_core::mouse;
use iced_core::overlay;
use iced_core::renderer;
use iced_core::touch;
use iced_core::widget::Operation;
use iced_core::widget::tree::{self, Tree};
use iced_core::{
    Clipboard, Element, Event, Layout, Length, Padding, Rectangle, Shell, Size, Vector, Widget,
};

pub struct Container<'a, Message, Theme = iced::Theme, Renderer = iced::Renderer>
where
    Renderer: iced_core::Renderer,
{
    content: Element<'a, Message, Theme, Renderer>,
    gutter: f32,
    on_hover: Option<Message>,
    on_leave: Option<Message>,
    on_click: Option<Message>,
    show_clickable: bool,
}

impl<'a, Message, Theme, Renderer> Container<'a, Message, Theme, Renderer>
where
    Renderer: iced_core::Renderer,
{
    pub fn new(content: impl Into<Element<'a, Message, Theme, Renderer>>) -> Self {
        Container {
            content: content.into(),
            gutter: 0.0,
            on_hover: None,
            on_leave: None,
            on_click: None,
            show_clickable: false,
        }
    }

    pub fn gutter(mut self, gutter: f32) -> Self {
        self.gutter = gutter;
        self
    }

    pub fn on_hover(mut self, on_hover: Message) -> Self {
        self.on_hover = Some(on_hover);
        self
    }

    pub fn on_leave(mut self, on_leave: Message) -> Self {
        self.on_leave = Some(on_leave);
        self
    }

    pub fn on_click(mut self, on_click: Message) -> Self {
        self.on_click = Some(on_click);
        self
    }

    pub fn show_clickable(mut self, show_clickable: bool) -> Self {
        self.show_clickable = show_clickable;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct State {
    is_hovered: bool,
}

impl<'a, Message, Theme, Renderer> Widget<Message, Theme, Renderer>
    for Container<'a, Message, Theme, Renderer>
where
    Message: 'a + Clone,
    Renderer: 'a + iced_core::Renderer,
{
    fn tag(&self) -> tree::Tag {
        tree::Tag::of::<State>()
    }

    fn state(&self) -> tree::State {
        tree::State::new(State::default())
    }

    fn children(&self) -> Vec<Tree> {
        vec![Tree::new(&self.content)]
    }

    fn diff(&self, tree: &mut Tree) {
        tree.diff_children(std::slice::from_ref(&self.content));
    }

    fn size(&self) -> Size<Length> {
        self.content.as_widget().size_hint()
    }

    fn layout(
        &mut self,
        tree: &mut Tree,
        renderer: &Renderer,
        limits: &layout::Limits,
    ) -> layout::Node {
        let size = self.content.as_widget().size_hint();
        layout::padded(
            limits,
            size.width.fluid(),
            size.height.fluid(),
            Padding::default(),
            |limits| {
                self.content
                    .as_widget_mut()
                    .layout(&mut tree.children[0], renderer, limits)
            },
        )
    }

    fn operate(
        &mut self,
        tree: &mut Tree,
        layout: Layout<'_>,
        renderer: &Renderer,
        operation: &mut dyn Operation,
    ) {
        operation.container(None, layout.bounds());
        operation.traverse(&mut |operation| {
            self.content.as_widget_mut().operate(
                &mut tree.children[0],
                layout.children().next().unwrap(),
                renderer,
                operation,
            );
        });
    }

    fn update(
        &mut self,
        tree: &mut Tree,
        event: &Event,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        renderer: &Renderer,
        clipboard: &mut dyn Clipboard,
        shell: &mut Shell<'_, Message>,
        viewport: &Rectangle,
    ) {
        let state = tree.state.downcast_mut::<State>();
        let new = cursor.is_over(layout.bounds().expand(self.gutter));
        if state.is_hovered && !new {
            if let Some(message) = self.on_leave.take() {
                shell.publish(message);
            }
        }
        if !state.is_hovered && new {
            if let Some(message) = self.on_hover.take() {
                shell.publish(message);
            }
        }
        state.is_hovered = new;

        if state.is_hovered {
            match event {
                Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left))
                | Event::Touch(touch::Event::FingerPressed { .. }) => {
                    if let Some(message) = self.on_click.take() {
                        shell.publish(message);
                    }
                }
                _ => {}
            }
        }

        self.content.as_widget_mut().update(
            &mut tree.children[0],
            event,
            layout.children().next().unwrap(),
            cursor,
            renderer,
            clipboard,
            shell,
            viewport,
        );
    }

    fn draw(
        &self,
        tree: &Tree,
        renderer: &mut Renderer,
        theme: &Theme,
        style: &renderer::Style,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
    ) {
        self.content.as_widget().draw(
            &tree.children[0],
            renderer,
            theme,
            style,
            layout.children().next().unwrap(),
            cursor,
            &viewport,
        );
    }

    fn mouse_interaction(
        &self,
        tree: &Tree,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
        renderer: &Renderer,
    ) -> mouse::Interaction {
        if self.show_clickable && cursor.is_over(layout.bounds()) {
            return mouse::Interaction::Pointer;
        }

        self.content.as_widget().mouse_interaction(
            &tree.children[0],
            layout.children().next().unwrap(),
            cursor,
            viewport,
            renderer,
        )
    }

    fn overlay<'b>(
        &'b mut self,
        tree: &'b mut Tree,
        layout: Layout<'b>,
        renderer: &Renderer,
        viewport: &Rectangle,
        translation: Vector,
    ) -> Option<overlay::Element<'b, Message, Theme, Renderer>> {
        self.content.as_widget_mut().overlay(
            &mut tree.children[0],
            layout.children().next().unwrap(),
            renderer,
            viewport,
            translation,
        )
    }
}

impl<'a, Message, Theme, Renderer> From<Container<'a, Message, Theme, Renderer>>
    for Element<'a, Message, Theme, Renderer>
where
    Message: Clone + 'a,
    Theme: 'a,
    Renderer: iced_core::Renderer + 'a,
{
    fn from(button: Container<'a, Message, Theme, Renderer>) -> Self {
        Self::new(button)
    }
}
