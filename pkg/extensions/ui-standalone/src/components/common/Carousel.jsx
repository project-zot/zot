import React from 'react';

const KEY_CODES = {
    LEFT_ARROW: 37,
    DOWN_ARROW: 40,
};

class Carousel extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            selectedSlide: 0,
            numSlides: React.Children.count(props.children)
        };
    }

    componentDidMount() {
        document.addEventListener('keydown', this.handleKeyDown);
    }

    componentWillUnmount() {
        document.removeEventListener('keydown', this.handleKeyDown);
    }

    getSlides() {
        const {children} = this.props;
        const {selectedSlide} = this.state;
        return React.Children.map(children, (child, idx) => {
            const slideClassName = idx === selectedSlide ? 'active' : '';
            return (
                <div id={`slide-idx-${idx}`} className={`carousel__slide ${slideClassName}`}>
                    {child}
                </div>
            );
        });
    }

    getControls() {
        const {children} = this.props;
        const {selectedSlide} = this.state;
        return React.Children.map(children, (child, idx) => {
            const ctrlClassName = idx === selectedSlide ? 'active' : '';
            return (
                <a id={`slide-idx-${idx}`} className={`dot ${ctrlClassName}`}><span className="icon-circle" /></a>
            );
        });
    }

    moveToStep(stepIdx) {
        const {numSlides} = this.state;
        switch (true) {
            case stepIdx >= numSlides:
                stepIdx = 0;
                break;
            case stepIdx < 0:
                stepIdx = numSlides - 1;
                break;
            default:
                break;
        }
        this.setState({
            selectedSlide: stepIdx
        });
    }

    next = () => {
        const {selectedSlide} = this.state;
        this.moveToStep(selectedSlide + 1);
    };

    prev = () => {
        const {selectedSlide} = this.state;
        this.moveToStep(selectedSlide - 1);
    };

    handleKeyDown = (e) => {
        switch (e.keyCode) {
            case KEY_CODES.LEFT_ARROW:
                this.prev();
                break;
            case KEY_CODES.RIGHT_ARROW:
                this.next();
                break;
            default:
                break;
        }
        return true;
    };

    render() {
        return (
            <div className="carousel">
                {this.getSlides()}
                <div className="carousel__controls">
                    <a className="back" onClick={this.prev}>
                        <span className="icon-chevron-left" />
                    </a>
                    {this.getControls()}
                    <a className="next" onClick={this.next}>
                        <span className="icon-chevron-right" />
                    </a>
                </div>
            </div>
        );
    }
}

export {Carousel};
